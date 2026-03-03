# Flow Logic: Patient Profile Management

This document explains the logic for retrieving and updating patient profiles, focusing on the data aggregation and security patterns used in the system.

---

## 🏗️ 1. Backend: Service Implementation
**File**: `PatientServiceImpl.java`

This service manages the patient data lifecycle, ensuring that profile information is correctly retrieved, updated, and sanitized.

### Line-by-Line Breakdown:

| Line of Code | Explanation | Logic / Purpose |
| :--- | :--- | :--- |
| `userRepository.findById(id)` | Fetches the `User` entity from the database by its ID. | **Data Source**: The starting point for all profile lookups. |
| `if (!user.getRole().equals(Role.ROLE_PATIENT))` | Checks if the retrieved user has the correct role. | **Security**: Prevents unauthorized access or modification of non-patient accounts. |
| `mapToPatientResponse(user)` | Private helper to convert the Entity to a DTO. | **Data Sanitization**: Prevents leaking sensitive fields like passwords. |
| `response.setVitals(vitalsService.getLatestVitals(...))` | Hydrates the profile with health data. | **Data Aggregation**: Combines account info with medical records in one response. |
| `if (dto.getFirstName() != null) user.setFirstName(...)` | Conditional check for the new first name. | **Partial Update**: Allows updating only specific fields without requiring all data. |
| `userRepository.save(user)` | Persists the modified Java object back to the database. | **Persistence**: Makes the updates permanent. |

---

## 🌐 2. Frontend: Dashboard Integration
**File Path**: `patient.service.ts` -> `getPatientById()` | `updatePatientProfile()`

The frontend uses these services to populate the profile settings page and send updates back to the server.

### Line-by-Line Breakdown:

| Line of Code | Explanation | Logic / Purpose |
| :--- | :--- | :--- |
| `getPatientById(id: number)` | Triggers an HTTP GET request to `/api/patients/{id}`. | **Read Action**: Loads the patient's data when they open the profile page. |
| `updatePatientProfile(id, data)` | Triggers an HTTP PUT request to `/api/patients/{id}`. | **Write Action**: Sends the modified profile fields to the backend for storage. |
| `subscribe({ next: (res) => ... })` | Listens for the server's confirmation. | **UI Update**: Refreshes the local display or shows a success toast. |

---

## 📝 3. End-to-End Flow Summary
1.  **View**: A patient logs in and navigates to the **Profile** page.
2.  **Request**: The frontend requests the patient data by ID.
3.  **Process**: The backend fetches the `User`, verifies they are a **Patient**, attaches their **Latest Vitals**, and returns a sanitized `PatientResponse`.
4.  **Edit**: The patient changes their **Email** or **Gender** and clicks **Save**.
5.  **Update**: The frontend sends a `PUT` request with only the changed fields.
6.  **Persistence**: The backend updates the database row and returns the freshly updated profile to the UI.
