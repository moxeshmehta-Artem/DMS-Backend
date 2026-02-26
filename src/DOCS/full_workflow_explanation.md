# DMS: End-to-End Workflow Explanation

This document traces a single, complete workflow: **"Viewing Patient Details"**. It shows how data travels from the user's click in the browser, through security and the backend, to the database, and back to the screen.

---

## 🔄 Trace: "View Patient Details"

### Phase 1: The Request (Frontend)
1.  **User Action**: A Dietitian clicks the "View Patient Details" button in the Patient List.
2.  **Component**: `PatientListComponent.viewPatientDetails()` is triggered within [patient-list.component.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/patient-list/patient-list.component.ts).
3.  **Service**: It calls `PatientService.getPatientById(id)` which uses Angular's `HttpClient`.
4.  **Interceptor**: Before the request leaves the browser, the [auth.interceptor.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/auth/auth.interceptor.ts) attaches the **JWT Token** to the `Authorization` header.

### Phase 2: Border Control (Backend Security)
5.  **CORS Check**: The request arrives at the Spring Boot server. [WebSecurityConfig](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/WebSecurityConfig.java) verifies it is coming from the trusted origin `http://localhost:4200`.
6.  **JWT Validation**: The `JwtInterceptor` extracts the token, verifies it using the `jwtSecret`, and extracts the user's identity and role.

### Phase 3: Business Logic (Backend Processing)
7.  **Controller**: The request is routed to `PatientController.getPatientById()`.
8.  **Authorization**: The `@RequireRole` annotation checks if the user has the correct permissions (e.g., `ROLE_DIETITIAN`).
9.  **Service Layer**: `PatientService` receives the request and fetches the data from the `UserRepository`.

### Phase 4: Data Layer (Database)
10. **Repository**: `UserRepository` executes a JQL/SQL query: `SELECT * FROM users WHERE id = ?`.
11. **Database**: MySQL finds the record in the `users` table and returns the raw **Entity** object.

### Phase 5: The Response (Formatting & Security)
12. **Mapping**: The backend maps the raw **User Entity** (which contains sensitive data like hashed passwords) to a safe **PatientResponse DTO**.
13. **JSON Delivery**: The DTO is serialized into a JSON object and sent back to the frontend with an HTTP `200 OK` status.

### Phase 6: Rendering (Frontend Update)
14. **Subscription**: The Angular component receives the JSON data in its `.subscribe()` block.
15. **Display**: The data is bound to `this.selectedPatientDetails`, which triggers the UI to display the details modal on the user's screen.

---

## 🔑 Key Concepts Used
- **JWT (Stateless Auth)**: Ensures you don't need a session on the server.
- **Interceptors**: Automate the "heavy lifting" of adding tokens.
- **DTOs (Data Transfer Objects)**: Protect your database structure and sensitive fields.
- **Role-Based Access Control (RBAC)**: Ensures users can only see what they are allowed to see.
