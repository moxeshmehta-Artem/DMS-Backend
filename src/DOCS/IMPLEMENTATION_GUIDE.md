# System Implementation Guide: DMS-Backend

This document provides a technical overview of the architectural patterns and optimizations implemented in the Diet Management System (DMS) Backend.

---

## 🏗️ Architectural Patterns

### 1. The Facade Pattern (Service Layer)
We use the **Facade** pattern in the Service layer to simplify complex operations.
- **Example**: [AppointmentServiceImpl.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/service/impl/AppointmentServiceImpl.java)
- **Role**: It acts as a single point of entry for the Controller, coordinating multiple repositories (User, Vitals, Schedule) so the Controller doesn't have to manage multiple dependencies.

### 2. DTO (Data Transfer Object) Pattern
To protect the database and optimize network traffic, we never expose Entities directly.
- **Request DTOs**: Capture user input (e.g., `AppointmentRequest`).
- **Response DTOs**: Sanitized data sent to the Frontend (e.g., `AppointmentResponse`).
- **Optimization**: Use **MapStruct** for automatic, high-performance mapping between Entities and DTOs.

### 3. Repository & Projection Pattern
We use **Spring Data JPA Projections** to optimize database performance.
- **Interface Projections**: Used in `UserRepository` to fetch only specific columns (like ID and Name) for dropdowns, avoiding the "Lazy Loading" overhead of full Entities.

---

## ⚡ Key Optimizations

### 1. JPA Auditing (Auto-Timestamps)
We have enabled **JPA Auditing** to automate administrative fields.
- **Config**: [JpaConfig.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/JpaConfig.java)
- **Usage**: Entities like `Appointment` and `Vitals` use `@CreatedDate` and `@LastModifiedDate`.
- **Benefit**: Removes manual boilerplate code from every `save` and `update` operation.

### 2. Exception-Based API Responses
We have moved away from returning error flags in DTOs in favor of a **Global Exception Handling** strategy.
- **Mechanism**: Services throw custom exceptions (e.g., `BookingConflictException`).
- **Handler**: [GlobalExceptionHandler.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/exception/GlobalExceptionHandler.java) catches these and returns a standardized JSON object with professional error details.

---

## 🛡️ Security Hardening

### 1. Environment Variable Injection
All sensitive secrets (JWT Keys, Database Credentials) are stored in environment variables using the `${VAR:DEFAULT}` pattern. This prevents accidental exposure of secrets in the source code.

### 2. Strict CORS Policy
CORS is managed globally in [WebSecurityConfig.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/WebSecurityConfig.java). 
- **Security Check**: Local `@CrossOrigin("*")` overrides have been removed to ensure the application only communicates with authorized origins.

---

## 🚀 Future Recommendations
- **Java Records**: Migrate DTOs to Java 17 Records to reduce code size by another 10-15%.
- **Integration Tests**: Implement `@DataJpaTest` and `@SpringBootTest` to verify the "Facade" logic automatically.
