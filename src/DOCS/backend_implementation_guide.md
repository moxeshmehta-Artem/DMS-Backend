# DMS Backend Implementation Guide (Spring Boot + MySQL)

This checklist tracks the development of the Diet Management System (DMS) backend, strictly following the layered architecture `controller -> service -> repository -> entity`.

## 1. Project Initialization & Configuration
- [ ] **Dependency Management (pom.xml)**
    - [x] Spring Boot Starter Web
    - [x] Spring Boot Starter Data JPA
    - [x] MySQL Driver
    - [x] Validation Starter
    - [x] Security Starter & JWT (JJWT)
    - [ ] **Add Lombok** (Reduce boilerplate).
    - [ ] **Add ModelMapper/MapStruct** (DTO conversion).
- [ ] **Database Configuration**
    - [x] Create MySQL database `DMS-DB`.
    - [x] Configure [application.properties](file:///home/artem/Desktop/DMS-Main/DMS-Backend/target/classes/application.properties).
- [ ] **Folder Structure Setup**
    - [ ] Ensure packages exist: `config`, `controllers`, `dto`, `models`, `exceptions`, `repositories`, `security`, `services`, `utils`.

## 2. Authentication & Security Module
- [ ] **Security Architecture & Config**
    - [ ] Implement `SecurityConfig` (SecurityFilterChain).
        - [ ] Disable CSRF.
        - [ ] Configure `SessionCreationPolicy.STATELESS`.
        - [ ] Configure CORS (Allow frontend origin).
        - [ ] Define public endpoints (`/api/v1/auth/**`).
    - [ ] Implement `AuthEntryPointJwt` (Custom 401 Unauthorized handler).
- [ ] **Domain Entities (Auth)**
    - [ ] Create `User` Entity (Implements `UserDetails` or wrapper).
        - [ ] Fields: `id`, `username`, `email`, `password`, `firstName`, `lastName`, `role` (Enum), `phone`, `dob`.
        - [ ] Audit Fields: `createdAt`, `updatedAt`.
    - [ ] Create `Role` Enum (`ROLE_ADMIN`, `ROLE_DOCTOR`, `ROLE_DIETITIAN`, `ROLE_PATIENT`, `ROLE_FRONTDESK`).
    - [ ] Create `UserRepository`: `findByUsername`, `existsByUsername`, `existsByEmail`.
- [ ] **JWT Core Service**
    - [ ] Implement `JwtUtils`:
        - [ ] `generateJwtToken(authentication)`.
        - [ ] `validateJwtToken(token)`.
        - [ ] `getUserNameFromJwtToken(token)`.
    - [ ] Implement `AuthTokenFilter`:
        - [ ] Intercept requests -> Extract Token -> Validate -> Set SecurityContext.
    - [ ] Implement `UserDetailsServiceImpl`: Load user from DB.
- [ ] **Auth Business Logic (`AuthService`)**
    - [ ] `registerUser(SignupRequest)`: Validate, Encode Password, Save.
    - [ ] `authenticateUser(LoginRequest)`: Authenticate, Generate JWT.
- [ ] **Auth Endpoints (`AuthController`)**
    - [ ] `POST /api/v1/auth/register`: Signup.
    - [ ] `POST /api/v1/auth/login`: Returns `{ token, type, id, username, email, roles }`.

## 3. Patient Management Module
- [ ] **Patient Domain**
    - [ ] Create [Patient](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/services/appointment.service.ts#53-56) DTOs (`PatientResponse`, `PatientUpdateDTO`).
    - [ ] *Note: Patients are `Users` with `ROLE_PATIENT`. Logic might be in `UserService` or separate `PatientService` if specific fields exist.*
- [ ] **Patient Service**
    - [ ] `getAllPatients()`: List all users with `ROLE_PATIENT`.
    - [ ] `getPatientById(id)`: Validate role is PATIENT.
    - [ ] `updatePatientProfile(id, dto)`: Update non-auth details.
- [ ] **Patient Controller**
    - [ ] `GET /api/v1/patients` (Admin/Doctor/Dietitian only).
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
