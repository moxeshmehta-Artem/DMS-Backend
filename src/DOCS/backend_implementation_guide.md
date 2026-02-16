# DMS Backend Implementation Guide (Spring Boot + MySQL)

### Progress Summary
> **Current Status**: Project Initialized. **Authentication Module** acts as the foundation and is functionally complete (Login, Register).
> **Remaining Work**: The core business logic modules (Patient Profiles, Vitals, Appointments, Diet Plans) are **NOT YET IMPLEMENTED**.

This checklist tracks the development of the Diet Management System (DMS) backend, strictly following the layered architecture `controller -> service -> repository -> entity`.

## 1. Project Initialization & Configuration
- [x] **Dependency Management (pom.xml)**
    - [x] Spring Boot Starter Web
    - [x] Spring Boot Starter Data JPA
    - [x] MySQL Driver
    - [x] Validation Starter
    - [x] Security Starter & JWT (JJWT)
    - [x] **Add Lombok** (Reduce boilerplate).
    - [ ] **Add ModelMapper/MapStruct** (DTO conversion).
- [x] **Database Configuration**
    - [x] Create MySQL database `DMS-DB`.
    - [x] Configure [application.properties](file:///home/artem/Desktop/DMS-Main/DMS-Backend/target/classes/application.properties).
- [x] **Folder Structure Setup**
    - [x] Ensure packages exist: `config`, `controllers`, `dto`, `models`, `exceptions`, `repositories`, `security`, `services`, `utils`.

## 2. Authentication & Security Module (COMPLETED)
- [x] **Security Architecture & Config**
    - [x] Implement `SecurityConfig` (SecurityFilterChain).
        - [x] Disable CSRF.
        - [x] Configure `SessionCreationPolicy.STATELESS`.
        - [x] Configure CORS (Allow frontend origin).
        - [x] Define public endpoints (`/api/auth/**`).
    - [x] Implement `AuthEntryPointJwt` (Custom 401 Unauthorized handler).
- [x] **Domain Entities (Auth)**
    - [x] Create `User` Entity (Implements `UserDetails` or wrapper).
        - [x] Fields: `id`, `username`, `email`, `password`, `firstName`, `lastName`, `role` (Enum).
        - [ ] Audit Fields: `createdAt`, `updatedAt` (Bonus).
    - [x] Create `Role` Enum (`ROLE_ADMIN`, `ROLE_DOCTOR`, `ROLE_DIETITIAN`, `ROLE_PATIENT`, `ROLE_FRONTDESK`).
    - [x] Create `UserRepository`: `findByUsername`, `existsByUsername`, `existsByEmail`.
- [x] **JWT Core Service**
    - [x] Implement `JwtUtils`:
        - [x] `generateJwtToken(authentication)`.
        - [x] `validateJwtToken(token)`.
        - [x] `getUserNameFromJwtToken(token)`.
    - [x] Implement `AuthTokenFilter`:
        - [x] Intercept requests -> Extract Token -> Validate -> Set SecurityContext.
    - [x] Implement `UserDetailsServiceImpl`: Load user from DB.
- [x] **Auth Business Logic (`AuthService`)**
    - [x] `registerUser(SignupRequest)`: Validate, Encode Password, Save.
    - [x] `authenticateUser(LoginRequest)`: Authenticate, Generate JWT.
- [x] **Auth Endpoints (`AuthController`)**
    - [x] `POST /api/auth/register`: Signup.
    - [x] `POST /api/auth/login`: Returns `{ token, type, id, username, email, roles }`.

## 3. Patient Management Module (COMPLETED)
- [x] **Patient Domain**
    - [x] Create [Patient](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/services/appointment.service.ts#53-56) DTOs (`PatientResponse`, `PatientUpdateDTO`).
    - [x] *Note: Patients are `Users` with `ROLE_PATIENT`. Logic is in `UserController`.*
    - [x] Added `gender` field to User entity and response.
- [x] **Patient Service**
    - [x] `getAllPatients()`: List all users with `ROLE_PATIENT` (Implemented in Controller).
    - [x] `getPatientById(id)`: Validate role is PATIENT.
    - [x] `updatePatientProfile(id, dto)`: Update non-auth details.
- [x] **Patient Controller**
    - [x] `GET /api/v1/patients` (Implemented as `/api/users/patients`).
    - [x] `GET /api/v1/patients/{id}`.
    - [x] `PUT /api/v1/patients/{id}`.
- [x] **Utils**
    - [x] `DataSeeder`: Initialize default Admin, Frontdesk, Dietitian, and Patient accounts on startup.
    - [x] `GET /api/users/dietitians`: endpoint to fetch all dietitians.

## 4. Vitals Module
- [ ] **Vitals Domain**
    - [ ] Create `Vitals` Entity.
        - [ ] Fields: `id`, `patient` (ManyToOne), `height`, `weight`, `bmi`, `bloodPressureSys`, `bloodPressureDia`, `heartRate`, `temperature`, `recordedAt`.
    - [ ] Create `VitalsRepository`.
- [ ] **Vitals Logic (Service)**
    - [ ] Create `VitalsService`.
        - [ ] `addVitals(patientId, VitalsRequest)`: Validates input, calculates BMI automatically, saves to DB.
        - [ ] `getVitalsHistory(patientId)`: Returns list of vitals sorted by `recordedAt` desc.
- [ ] **Vitals API (Controller)**
    - [ ] Create `VitalsController`.
        - [ ] `POST /api/v1/patients/{patientId}/vitals`: Record new vitals. Request body: `VitalsRequest`.
        - [ ] `GET /api/v1/patients/{patientId}/vitals`: Get history. Response: `List<VitalsResponse>`.
    - [ ] Create DTOs:
        - [ ] `VitalsRequest`: Input fields (height, weight, etc.).
        - [ ] `VitalsResponse`: Output fields (including calculated BMI).

## 5. Appointment Module (Scheduling) (PARTIALLY COMPLETED)
- [x] **Appointment Domain**
    - [x] Create `Appointment` Entity.
        - [x] Fields: `id`, `patient` (ManyToOne), `dietitian` (ManyToOne), `appointmentDate`, `timeSlot`, `status` (Enum), `description`, `notes`.
        - [x] Enums: `PENDING`, `CONFIRMED`, `REJECTED`, `COMPLETED`, `CANCELLED`.
    - [x] Create `AppointmentRepository`.
        - [x] `findByPatient`, `findByDietitian`, `findByAppointmentDateAndDietitian`.
- [x] **Appointment Service**
    - [x] `bookAppointment(request)`: Check slot availability first.
    - [x] `updateStatus(id, status, notes)`: Confirmed/Rejected/Completed.
    - [x] `getAllAppointments()`: Returns all appointments (Used by Frontdesk Dashboard).
    - [x] `getPatientAppointments(patientId)`.
    - [x] `getProviderAppointments(providerId)`.
- [x] **Appointment Controller**
    - [x] `POST /api/v1/appointments`: Book.
    - [x] `GET /api/v1/appointments`: Fetch all.
    - [x] `GET /api/v1/appointments/patient/{patientId}`.
    - [x] `GET /api/v1/appointments/provider/{providerId}`.
    - [x] `PUT /api/v1/appointments/{id}/status`.

## 6. Diet Plans Module
- [ ] **Diet Plan Domain**
    - [ ] Create `DietPlan` Entity.
        - [ ] Fields: `id`, `patient` (ManyToOne), `assignedBy` (ManyToOne), `breakfast`, `lunch`, `dinner`, `snacks`, `createdAt`.
    - [ ] Create `DietPlanRepository`.
- [ ] **Diet Plan Service**
    - [ ] `createDietPlan(request)`: Assign to patient.
    - [ ] `getLatestDietPlan(patientId)`.
    - [ ] `getDietPlanHistory(patientId)`.
- [ ] **Diet Plan Controller**
    - [ ] `POST /api/v1/patients/{id}/diet-plans`.
    - [ ] `GET /api/v1/patients/{id}/diet-plans`.

## 7. Cross-Cutting & Utilities
- [ ] **Global Exception Handling**
    - [ ] `@ControllerAdvice`: Handle `EntityNotFound`, `BadCredentials`.
    - [ ] Standard JSON Error Response.
- [ ] **Validation**
    - [ ] Apply `@Valid` on all RequestBodies.
    - [ ] DTO Validation annotations (`@NotNull`, `@Size`, etc.).
- [x] **CORS Configuration**
    - [x] Allow requests from `http://localhost:4200` (Angular).

## 8. Performance & Dashboard Optimization (RECOMMENDED)
- [ ] **Summary Dashboard Endpoint**
    - [ ] Create `GET /api/v1/dashboard/summary` to return pre-calculated counts and chart data (Avoid fetching full lists).
- [ ] **Pagination**
    - [ ] Implement `Pageable` support for `GET /api/users/patients` and `GET /api/v1/appointments`.
- [ ] **Targeted Queries**
    - [ ] Optimize "Today's Appointments" query to only fetch relevant date range.
