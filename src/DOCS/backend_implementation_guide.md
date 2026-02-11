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

## 3. Patient Management Module
- [x] **Patient Domain**
    - [x] Create [Patient](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/services/appointment.service.ts#53-56) DTOs (`PatientResponse`, `PatientUpdateDTO`).
    - [x] *Note: Patients are `Users` with `ROLE_PATIENT`. Logic is in `UserController`.*
    - [x] Added `gender` field to User entity and response.
- [ ] **Patient Service**
    - [x] `getAllPatients()`: List all users with `ROLE_PATIENT` (Implemented in Controller).
    - [ ] `getPatientById(id)`: Validate role is PATIENT.
    - [ ] `updatePatientProfile(id, dto)`: Update non-auth details.
- [ ] **Patient Controller**
    - [x] `GET /api/v1/patients` (Implemented as `/api/users/patients`).
    - [ ] `GET /api/v1/patients/{id}`.
    - [ ] `PUT /api/v1/patients/{id}`.

## 4. Vitals Module
- [ ] **Vitals Domain**
    - [ ] Create `Vitals` Entity.
        - [ ] Fields: `id`, `patient` (ManyToOne), `height`, `weight`, `bmi`, `bpSystolic`, `bpDiastolic`, `heartRate`, `temperature`, `recordedAt`.
    - [ ] Create `VitalsRepository`.
- [ ] **Vitals Service**
    - [ ] `addVitals(patientId, VitalsRequest)`: Calculate BMI automatically?
    - [ ] `getVitalsHistory(patientId)`: Return list sorted by date.
- [ ] **Vitals Controller**
    - [ ] `POST /api/v1/patients/{patientId}/vitals`.
    - [ ] `GET /api/v1/patients/{patientId}/vitals`.

## 5. Appointment Module (Scheduling)
- [ ] **Appointment Domain**
    - [ ] Create [Appointment](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/services/appointment.service.ts#77-90) Entity.
        - [ ] Fields: `id`, `patient` (ManyToOne), `provider` (ManyToOne), `appointmentDate`, `timeSlot`, `status` (Enum), `description`, `notes`.
        - [ ] Enums: `PENDING`, `CONFIRMED`, `REJECTED`, `COMPLETED`, `CANCELLED`.
    - [ ] Create `AppointmentRepository`.
        - [ ] `findByPatientId`, `findByProviderId`, `findByDateAndProvider`.
- [ ] **Appointment Service**
    - [ ] [bookAppointment(request)](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/services/appointment.service.ts#77-90): Check slot availability first.
    - [ ] [updateStatus(id, status)](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/services/appointment.service.ts#91-97): Confirmed/Rejected/Completed.
    - [ ] `addNotes(id, notes)`: Doctor adds clinical notes.
    - [ ] `getAvailableSlots(providerId, date)`: Logic to calculate free slots.
- [ ] **Appointment Controller**
    - [ ] `POST /api/v1/appointments`: Book.
    - [ ] `GET /api/v1/appointments`: Filter by date/doctor/patient.
    - [ ] `PUT /api/v1/appointments/{id}/status`.

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
- [ ] **CORS Configuration**
    - [ ] Allow requests from `http://localhost:4200` (Angular).
