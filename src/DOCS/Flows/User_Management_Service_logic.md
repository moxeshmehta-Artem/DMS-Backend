# Flow Logic: User Management & Data Aggregation

This document explains the logic within `UserServiceImpl.java`, focusing on how the system efficiently fetches large amounts of data and safely deletes users.

---

## 🏗️ 1. Batch Fetching Logic (`getAllPatients`)
This method is designed for **High Performance**. Instead of making 100 separate database calls for 100 patients, it uses a **Batch Pattern**.

### Line-by-Line Breakdown:

| Line of Code | Logic / Purpose | Example Scenario |
| :--- | :--- | :--- |
| `userRepository.findByRole(Role.ROLE_PATIENT)` | Fetches the base list of all patients. | **Result**: A list of 50 patients starts in memory. |
| `vitalsService.getLatestVitalsForPatients(patients)` | **Batch Call**: Asks for the latest vitals for all 50 people in *one* request. | Instead of 50 SQL queries, only **1** query is run: `SELECT * FROM vitals WHERE patient_id IN (1, 2, ... 50)`. |
| `vitalsMap = allLatestVitals.stream().collect(...)` | Converts the list into a "Quick Lookup" Map. | **Result**: A Map indexed by `patientId` for instant retrieval. |
| `appointmentRepository.findLatestAppointmentsByPatients(...)` | **Batch Call**: Finds the most recent appointment for every patient at once. | Prevents the **"N+1 problem"** (where N patients cause N+1 database hits). |
| `patients.stream().map(user -> { ... })` | Loops through patients and "plugs in" their specific vitals and appointments. | **John Doe**'s vitals are pulled from the Map and added to his `PatientResponse`. |

### 🚀 Performance Impact
*   **Without this logic**: 50 patients = 101 database calls.
*   **With this logic**: 50 patients = **3** database calls.

---

## 🛡️ 2. Safe Deletion Logic (`deleteUser`)
Deleting a user is complex because they have data in many tables (Appointments, Vitals, Diet Plans). If you just delete the user, the database will crash due to **Foreign Key Constraints**.

### Cleanup Steps:

| Step | Action | Why? |
| :--- | :--- | :--- |
| **1. Cleanup Appointments** | `appointmentRepository.deleteAll(pAppts / dAppts)` | Removes any booked meetings for this user so the appointment table stays clean. |
| **2. Cleanup Schedules** | `dietitianScheduleRepository.deleteAll(...)` | If the user is a Dietitian, their work shifts must be removed. |
| **3. Cleanup Diet Plans** | `dietPlanRepository.deleteAll(...)` | Removes all meal plans assigned to or by this user. |
| **4. Cleanup Vitals** | `vitalsRepository.deleteAll(...)` | Removes all health metrics history. |
| **5. Final Delete** | `userRepository.delete(user)` | Now that all "child" records are gone, the "parent" user can be safely deleted. |

### 🌟 Example Scenario
**Admin deletes Dietitian "Sarah":**
1. System finds all 10 appointments Sarah has next week. **Deleted.**
2. System finds Sarah's Mon-Fri 9-5 work schedule. **Deleted.**
3. System finds 50 diet plans Sarah wrote for patients. **Deleted.**
4. **Final Step**: Sarah's account is removed from the `users` table. **No error occurs.**

---

## 📝 3. Summary of Design Patterns
1.  **Aggregation (DTO Pattern)**: The `PatientResponse` is used to combine 3 different tables (Users, Vitals, Appointments) into one JSON object.
2.  **Map-Reduce Logic**: Using `Collectors.toMap` for O(1) lightning-fast lookups during result building.
3.  **Transactional Integrity**: The `@Transactional` annotation on `deleteUser` ensures that if one cleanup step fails, *nothing* is deleted, preventing "broken" data.
