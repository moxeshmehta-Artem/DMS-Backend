# DMS: End-to-End Workflow Explanation

This document traces a single, complete workflow: **"Viewing Patient Details"**. It shows how data travels from the user's click in the browser, through security and the backend, to the database, and back to the screen.

---

## 🔄 Trace: "View Patient Details" (File-to-File)

### Phase 1: The Request (Frontend)
1.  **Click**: `patient-list.component.html` (UI Button)
    $\rightarrow$ calls [patient-list.component.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/patient-list/patient-list.component.ts) (`viewPatientDetails`)
2.  **API Call**: [patient-list.component.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/patient-list/patient-list.component.ts)
    $\rightarrow$ calls [patient.service.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/services/patient.service.ts) (`getPatientById`)
3.  **Token Attachment**: [auth.interceptor.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/auth/auth.interceptor.ts)
    $\rightarrow$ Automatically attaches JWT from `AuthService`.

### Phase 2: Border Control (Backend Security)
4.  **CORS/Gate**: [WebSecurityConfig.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/WebSecurityConfig.java)
    $\rightarrow$ Validates `localhost:4200` origin.
5.  **Auth Validation**: [JwtInterceptor.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/JwtInterceptor.java)
    $\rightarrow$ Uses [JwtUtils.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/security/jwt/JwtUtils.java) to verify token.

### Phase 3: Business & Data Layers
6.  **Controller Entrance**: [PatientController.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/controllers/PatientController.java)
    $\rightarrow$ calls `PatientService` interface.
7.  **Service Logic**: [PatientServiceImpl.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/service/impl/PatientServiceImpl.java)
    $\rightarrow$ calls [UserRepository.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/repositories/UserRepository.java).
8.  **Database Access**: [UserRepository.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/repositories/UserRepository.java)
    $\rightarrow$ Fetches data from **MySQL `users` table**.

### Phase 4: Formatting & Return
9.  **Response Creation**: [PatientServiceImpl.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/service/impl/PatientServiceImpl.java)
    $\rightarrow$ Uses [PatientMapper.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/mapper/PatientMapper.java) to create [PatientResponse.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/dto/response/PatientResponse.java).
10. **JSON Response**: Serialized and sent back as JSON.
11. **UI Refresh**: [patient-list.component.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/patient-list/patient-list.component.ts)
    $\rightarrow$ Updates `selectedPatientDetails` and shows modal in `patient-list.component.html`.

---

## 🔑 Key Concepts Used
- **JWT (Stateless Auth)**: Ensures you don't need a session on the server.
- **Interceptors**: Automate the "heavy lifting" of adding tokens.
- **DTOs (Data Transfer Objects)**: Protect your database structure and sensitive fields.
- **Role-Based Access Control (RBAC)**: Ensures users can only see what they are allowed to see.
