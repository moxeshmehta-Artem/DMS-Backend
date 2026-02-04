# Database Schema Documentation (MySQL)

This document outlines the database schema for the Backend needed for the DMS (Doctor/Dietitian Management System). The schema is designed for a relational database (MySQL) using JPA.

## 1. Users Table (`users`)
Stores all system users (Patients, Doctors, Dietitians, Admins, Frontdesk).

| Column Name | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | BIGINT | PK, Auto Increment | Unique identifier |
| `username` | VARCHAR(50) | Unique, Not Null | Login username |
| `password` | VARCHAR(255) | Not Null | Hashed password |
| `email` | VARCHAR(100) | Unique, Not Null | Email address |
| `role` | VARCHAR(20) | Not Null | Enum: `ADMIN`, `DOCTOR`, `DIETITIAN`, `PATIENT`, `FRONTDESK` |
| `first_name` | VARCHAR(50) | Not Null | First name |
| `last_name` | VARCHAR(50) | Not Null | Last name |
| `phone` | VARCHAR(20) | | Contact number |
| `dob` | DATE | | Date of Birth |
| `gender` | VARCHAR(10) | | `Male`, `Female`, `Other` |
| `address` | TEXT | | Physical address |
| `created_at` | TIMESTAMP | Default CURRENT_TIMESTAMP | Record creation time |
| `updated_at` | TIMESTAMP | | Record update time |

## 2. Vitals Table (`vitals`)
Stores health vitals for patients. Linked to the `users` table via `patient_id`.

| Column Name | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | BIGINT | PK, Auto Increment | Unique identifier |
| `patient_id` | BIGINT | FK -> `users.id` | The patient these vitals belong to |
| `height` | DOUBLE | | Height in cm |
| `weight` | DOUBLE | | Weight in kg |
| `bmi` | DOUBLE | | Body Mass Index |
| `bp_systolic` | INT | | Blood Pressure (Systolic) |
| `bp_diastolic` | INT | | Blood Pressure (Diastolic) |
| `heart_rate` | INT | | Heart rate (bpm) |
| `temperature` | DOUBLE | | Body temperature (Celsius/Fahrenheit) |
| `recorded_at` | TIMESTAMP | Default CURRENT_TIMESTAMP | When these vitals were recorded |

## 3. Appointments Table (`appointments`)
Stores appointment details between patients and providers (Doctors/Dietitians).

| Column Name | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | BIGINT | PK, Auto Increment | Unique identifier |
| `patient_id` | BIGINT | FK -> `users.id` | The patient booking the appointment |
| `provider_id` | BIGINT | FK -> `users.id` | The Doctor or Dietitian |
| `appointment_date` | DATETIME | Not Null | Scheduled date and time |
| `time_slot` | VARCHAR(20) | | Display string (e.g., "10:00 AM") |
| `status` | VARCHAR(20) | Default 'PENDING' | Enum: `PENDING`, `CONFIRMED`, `REJECTED`, `COMPLETED` |
| `description` | TEXT | | Reason for appointment |
| `notes` | TEXT | | Doctor's notes after/during appointment |
| `created_at` | TIMESTAMP | Default CURRENT_TIMESTAMP | Booking time |

## 4. Diet Plans Table (`diet_plans`)
Stores diet plans assigned to patients.

| Column Name | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | BIGINT | PK, Auto Increment | Unique identifier |
| `patient_id` | BIGINT | FK -> `users.id` | Usage Target |
| `assigned_by` | BIGINT | FK -> `users.id` | Dietitian who created it |
| `breakfast` | TEXT | | Breakfast details |
| `lunch` | TEXT | | Lunch details |
| `dinner` | TEXT | | Dinner details |
| `snacks` | TEXT | | Snacks details |
| `created_at` | TIMESTAMP | Default CURRENT_TIMESTAMP | Creation date |

## 5. Doctor Details (`doctor_details`) - Optional / Extended
If doctors need significantly more specific fields (specialization, license number, availability), a separate table linked to `users` is recommended.

| Column Name | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `user_id` | BIGINT | PK, FK -> `users.id` | Link to user record |
| `specialization` | VARCHAR(100)| | e.g., "Cardiologist" |
| `license_number`| VARCHAR(50) | | Medical license number |
| `available_days`| VARCHAR(100)| | e.g., "MON,WED,FRI" |

## Relationships Summary

- **User (Patient)** `1:N` **Vitals**
- **User (Patient)** `1:N` **Appointments**
- **User (Provider)** `1:N` **Appointments**
- **User (Patient)** `1:N` **Diet Plans** (Usually a patient has one active plan, but history is kept)
