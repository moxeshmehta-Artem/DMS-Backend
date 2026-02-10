# Authentication System Documentation

This document explicitly details the login and registration workflow implemented in the Diet Management System (DMS), covering both Frontend (Angular) and Backend (Spring Boot).

## 1. Authentication Architecture

The system uses **JWT (JSON Web Token)** for stateless authentication.

*   **Frontend**: Angular Application (Port 4200)
    *   Manages user session via `localStorage`.
    *   Attaches JWT to every request using an `HttpInterceptor`.
*   **Backend**: Spring Boot Application (Port 8080)
    *   Exposes REST endpoints: `/api/auth/login` and `/api/auth/register`.
    *   Validates JWT on incoming requests via `AuthTokenFilter`.
*   **Database**: MySQL (Stores Users and Roles).

---

## 2. Detailed Workflows

### A. Patient Registration Flow

1.  **User Action**: 
    *   The Front Desk or Public User fills out the Registration Form at `/registration`.
    *   Fields: First Name, Last Name, Email, Username, Password, Vitals (Height, Weight, etc.).

2.  **Frontend Logic ([RegistrationComponent](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/registration/registration.component.ts#10-218))**:
    *   Collects form data.
    *   Calls `AuthService.registerPatient()`.

3.  **Frontend Service (`AuthService.ts`)**:
    *   Constructs a [SignupRequest](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/dto/request/SignupRequest.java#7-23) payload.
    *   **Crucial Logic**: explicitly sets `role: 'ROLE_PATIENT'` to match the backend enum.
    ```typescript
    registerPatient(userModel: User, password: string): Observable<any> {
        const signupRequest: SignupRequest = {
            username: userModel.username,
            email: userModel.email,
            password: password,
            role: 'ROLE_PATIENT', // MUST match backend enum exactly
            firstName: userModel.firstName,
            lastName: userModel.lastName
        };
        return this.http.post(`${this.API_URL}/register`, signupRequest);
    }
    ```

4.  **Backend Processing ([AuthService.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/service/AuthService.java))**:
    *   Receives `POST /api/auth/register`.
    *   Validates fields (username/email uniqueness).
    *   Creates a new [User](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/models/User.java#8-39) entity.
    *   **Crucial Logic**: Saves `firstName` and `lastName` to the [User](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/models/User.java#8-39) table.
    ```java
    public void registerUser(SignupRequest signUpRequest) {
        // ... existence checks ...
        User user = new User(
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                passwordEncoder.encode(signUpRequest.getPassword()),
                Role.valueOf(signUpRequest.getRole())); // Parses "ROLE_PATIENT"
        
        user.setFirstName(signUpRequest.getFirstName());
        user.setLastName(signUpRequest.getLastName());
        
        userRepository.save(user);
    }
    ```

### B. Dietitian Registration Flow (Admin Only)

1.  **User Action**: Admin logs in and goes to "Add Dietitian".
2.  **Frontend Service**:
    *   Calls `AuthService.registerDietitian()`.
    *   Sets `role: 'ROLE_DIETITIAN'`.
3.  **Backend**: Creates a user with `ROLE_DIETITIAN`.

### C. Login Flow

1.  **User Action**: Enters credentials at `/auth/login`.
2.  **Frontend Service**:
    *   Calls `POST /api/auth/login`.
3.  **Backend**:
    *   Authenticates credentials.
    *   Generates a signed JWT token containing the username and roles.
    *   Returns [JwtResponse](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/dto/response/JwtResponse.java#7-25).
4.  **Frontend Service**:
    *   Saves the [User](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/models/User.java#8-39) object (including `token`) to `localStorage`.
    *   Updates the `currentUser` signal.

---

## 3. Key Code Components

### Frontend: Role Handling
To ensure compatibility between Frontend mocks and Backend enums, the Frontend [AuthService](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/auth/auth.service.ts#34-210) handles role mapping:

```typescript
private mapBackendRoleToEnum(roles: string[]): Role {
    const roleStr = roles[0].replace('ROLE_', '').toUpperCase();
    if (roleStr === 'ADMIN') return Role.Admin;
    if (roleStr === 'DIETITIAN') return Role.Dietitian;
    if (roleStr === 'FRONTDESK') return Role.Frontdesk;
    return Role.Patient;
}
```

### Backend: DTOs
The [SignupRequest](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/dto/request/SignupRequest.java#7-23) DTO was updated to accept names:

```java
public class SignupRequest {
    @NotBlank
    private String username;
    @NotBlank
    @Email
    private String email;
    @NotBlank
    private String password;
    @NotBlank
    private String role; // e.g. "ROLE_PATIENT"
    
    // Added for DMS
    private String firstName;
    private String lastName;
}
```

## 4. Current Limitations
*   **Vitals**: While the Registration Form collects Vitals (Height, Weight, etc.), the current Backend [User](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/models/User.java#8-39) entity **does not** store them. They are currently dropped. A future task should create a [Patient](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/patient-list/patient-list.component.ts#112-144) entity linked to [User](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/models/User.java#8-39) to store this medical data.
