# 📊 DBMS Database Normalization Guide

Normalization is the process of organizing database fields and tables to minimize redundancy and dependency. It involves dividing large tables into smaller, related tables.

## 1. The "God Table" Problem
Our current `users` table stores everything for everyone. This leads to:
- **Null Values**: Doctors have no `age` or `gender` (in our system), and Patients have no `specialization`.
- **Inflexibility**: If we want to add "Years of Experience" for Dietitians, every Patient record gets a NULL column.
- **Data Integrity**: Harder to enforce rules like "a patient MUST have a DOB".

---

## 2. Proposed Normalized Structure

### A. Core Identity & Profiles
Instead of one `users` table, we split it based on **responsibility**:

#### `users` (Authentication)
- `id` (PK)
- `username`
- `email`
- `password`
- `role_id` (FK)

#### `profiles` (Common Metadata)
- `user_id` (FK, UNIQUE)
- `first_name`
- `last_name`
- `phone`
- `address_id` (FK)

#### `patient_details` (Patient Specific)
- `user_id` (FK, UNIQUE)
- `date_of_birth`
- `gender`
- `blood_group`
- `medical_history_summary`

#### `provider_details` (Doctor/Dietitian Specific)
- `user_id` (FK, UNIQUE)
- `specialization_id` (FK)
- `license_number`
- `consultation_fee`
- `bio`

---

### B. Reference Tables (Lookup Tables)
Instead of hardcoding strings in the database, use IDs that point to reference tables:

#### `roles`
- `id`
- `name` (ADMIN, DOCTOR, PATIENT)
- `description`

#### `specializations`
- `id`
- `name` (Nutritionist, Sports Dietitian, Clinical Dietitian)
- `department`

#### `appointment_statuses`
- `id`
- `name` (PENDING, CONFIRMED, CANCELLED)

---

### C. Feature Normalization (Expanding Capabilities)

#### `addresses`
Currently, "address" is just text. Normalized:
- `id`
- `street`
- `city`
- `state`
- `zip_code`
- `country`

#### `diet_plan_items` (Vertical Split)
Instead of `breakfast`, `lunch`, `dinner` as columns in `diet_plans`, we use a 1:N relationship:
- `id`
- `diet_plan_id` (FK)
- `meal_type` (FK to `meal_categories`)
- `description`
- `calories`
This allows for any number of meals (e.g., "Post-Workout Snack") without changing the table columns.

---

## 3. Benefits of this Approach
1.  **Better Integrity**: Role-specific fields are only populated for the correct users.
2.  **Scalability**: Adding a new user type (e.g., "Nurse") only requires a new detail table.
3.  **Performance**: Smaller tables mean faster index lookups and less wasted disk space.
4.  **Flexibility**: You can change a Specialization name in one place, and it updates everywhere.

## 4. Implementation Strategy
We will use **Flyway migrations** to:
1. Create new tables.
2. Migrating existing data from `users` to `patient_details` and `provider_details`.
3. Drop the old columns from `users`.
4. Update Java entities for `@OneToOne` and `@ManyToOne` relationships.
