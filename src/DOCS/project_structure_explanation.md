# DMS Project: Structure and Flow Explanation

The Dietitian Management System (DMS) is an enterprise-grade application for managing patient health, diet plans, and appointments. It consists of a modern Angular frontend and a robust Spring Boot backend.

## 1. Project Organization

The root directory contains:
- **`DMS/`**: The frontend application built with Angular.
- **`DMS-Backend/`**: The backend application built with Spring Boot.
- **`.vscode/`**: VS Code configuration (extensions, launch settings).

---

## 2. Frontend: `DMS/` (Angular)

Structured for modularity using standard Angular patterns.

### Core Folders in `src/app/`:
- **`core/`**: Centralized logic and singleton services.
  - `auth/`: Guards and JWT interceptors (e.g., `auth.guard.ts`).
  - `constants/`: Global constants (`permissions.ts`, `mock-data.ts`).
  - `models/`: TypeScript interfaces for data models.
  - `services/`: Data services (e.g., `PatientService`, `AppointmentService`).
- **`features/`**: Feature modules containing components and logic.
  - `dashboard/`, `appointments/`, `patient-list/`, `dietitian-management/`, etc.
- **`shared/`**: Reusable components, pipes, and validators.

---

## 3. Backend: `DMS-Backend/` (Spring Boot)

Follows a layered architecture for separation of concerns.

### Key Packages in `src/main/java/com/example/DMS_Backend/`:
- **`controllers/`**: REST API endpoints.
- **`service/`**: Business logic layer.
- **`entities/`**: JPA entities mapped to database tables.
- **`repositories/`**: Spring Data JPA repository interfaces.
- **`dto/`**: Data Transfer Objects for API communication.
- **`mapper/`**: MapStruct or custom mappers for Entity <-> DTO conversion.
- **`config/`**: Security and system configuration.
- **`exception/`**: Centralized error handling.

### Resources (`src/main/resources/`):
- `application.properties`: Configuration using environment variables for sensitive data.
- `db/migration/`: Flyway SQL migration scripts.

---

## 4. Application Flow

1.  **Frontend**: Triggers an action (e.g., booking an appointment).
2.  **Service**: `AppointmentService` makes an HTTP call to the backend.
3.  **Interceptor**: `authInterceptor` attaches the JWT token to the request.
4.  **Backend Controller**: Receives the request at `@PostMapping("/api/appointments")`.
5.  **Security**: Configured in `WebSecurityConfig.java` to validate the JWT and restrict CORS (Origins and Headers).
6.  **Service Layer**: Processes business rules (checking slot availability).
7.  **Data Layer**: Persists changes to MySQL via `Repository`.
8.  **Response**: DTO is returned to the frontend; UI updates automatically.

---

## 5. Security & Quality Hardening
- **CORS**: Restricted to `http://localhost:4200` with explicit headers (`Authorization`, `Content-Type`, etc.) to prevent CSRF and unauthorized cross-origin access.
- **Secrets**: Managed via environment variables in `application.properties` (e.g., `${JWT_SECRET}`) to prevent credential leakage.
- **Global Error Handling**: `GlobalExceptionHandler` ensures consistent API responses. It specifically handles:
    - **Validation Errors**: Extracts field-level errors from `@Valid` objects (MethodArgumentNotValidException).
    - **Resource/Patient Not Found**: Returns 404 with structured JSON.
    - **Runtime/Global Exceptions**: Prevents exposing internal stack traces by returning generic 500 errors.

---

## 6. Verification Tools
- **`.env.example`**: A template for required environment variables.
- **SQL Migrations**: Managed via Flyway in `src/main/resources/db/migration`.
