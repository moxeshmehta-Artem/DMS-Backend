# Project Technical Stack and Concepts: Frontend & Backend

This document provides a comprehensive list of the technologies, architectural patterns, and development concepts used in the Diet Management System (DMS).

---

## 🏗️ Backend Architecture (Java & Spring Boot)

The backend is built as a robust, secure, and scalable REST API using the **Spring Boot** framework.

### Core Technologies
*   **Java 17+**: Utilizing modern Java features like Records and the Stream API.
*   **Spring Boot**: The core framework for enterprise-ready application development.
*   **Spring Data JPA**: For streamlined database interactions and Object-Relational Mapping (ORM).
*   **MySQL**: The relational database used for production persistence.
*   **Lombok**: Reduces boilerplate code (e.g., `@Data`, `@Builder`, `@Getter`, `@Setter`, `@RequiredArgsConstructor`).

### Key Concepts & Patterns
*   **RESTful API Design**: High-quality endpoint design using `Controller` and `Service` layers.
*   **DTO Pattern**: Using Data Transfer Objects to separate the internal database model from the external API contract.
*   **Service Layer Pattern**: Decoupling business logic from API controllers for better testability and reusability.
*   **Stateless Authentication**: Implementing **JWT (JSON Web Tokens)** for secure, session-less auth.
*   **RBAC (Role-Based Access Control)**: custom security implementation using:
    *   **@RequireRole**: A custom annotation to enforce role permissions on specific methods.
    *   **JwtInterceptor**: A Spring interceptor that validates tokens and roles before reaching the controller.
*   **Password Hashing**: Secure password storage using **BCrypt** encoding.
*   **Transaction Management**: Ensuring data integrity using `@Transactional` annotations.
*   **Global Exception Handling**: Centralized error handling using `@RestControllerAdvice` and custom exceptions (e.g., `ResourceNotFoundException`).

### Persistence & Data Patterns
*   **Entity Lifecycle Hooks**: Using `@PrePersist` and `@PreUpdate` to automatically manage `createdAt` and `updatedAt` timestamps for auditing.
*   **Relationship Mapping**: Using JPA associations like `@ManyToOne` to link Appointments to Patients and Dietitians.
*   **Cascading Actions**: Enforcing data integrity with Hibernate-specific `@OnDelete(action = CASCADE)` to ensure related records (e.g., appointments) are cleaned up when a user is deleted.
*   **Database Constraints**: Using `@UniqueConstraint` at the entity level to prevent duplicate data, such as double-booking the same dietitian for the same day of the week.
*   **Data Seeding**: Automatically populating the database with default Admin, Frontdesk, and Dietitian users on startup using `CommandLineRunner`.

### Security & Interception
*   **Custom Handler Interceptor**: Implementing `JwtInterceptor` which leverages Spring MVC's `HandlerInterceptor` to validate JWTs and check for role presence on every request.
*   **Method-Level Authorization**: Using a custom `@RequireRole` annotation to restrict access to specific controller methods (e.g., `deleteUser` requires `ROLE_ADMIN`).
*   **Token Payload Mapping**: Extracting user information directly from JWT claims to populate request attributes for use in services and controllers.

---

## 🎨 Frontend Architecture (Angular)

The frontend is a modern Single Page Application (SPA) built with **Angular**, focusing on high performance and a premium user experience.

### Core Technologies
*   **Angular (Latest)**: Using **Standalone Components** to reduce module complexity.
*   **TypeScript**: Ensuring type safety throughout the application.
*   **RxJS**: Reactive programming using Observables for data streams and event handling.
*   **PrimeNG**: A premium UI component library (Card, Table, Toast, Dialog, Sidebar, etc.).
*   **SCSS**: Advanced CSS pre-processor for modular and scalable styling.

### Key Concepts & Patterns
*   **Signals Layer**: Utilizing **Angular Signals** (`signal<User | null>`) for lightweight and efficient state management.
*   **Dependency Injection**: Using the modern `inject()` function for clean service consumption.
*   **Angular Guards**: 
    *   `AuthGuard`: Prevents unauthorized access to protected routes.
    *   `NoAuthGuard`: Redirects logged-in users away from login/landing pages.
*   **JWT Interceptor**: Automatically attaches the bearer token to every outgoing HTTP request.
*   **Reactive Forms**: Type-safe form handling with extensive validation (e.g., `Validators.required`, `Validators.pattern`).
*   **Custom Validators**: Complex validation logic like `passwordMatchValidator`.
*   **Service-Based Data Fetching**: Centralizing API calls into specialized services (`AuthService`, `UserService`, `AppointmentService`).
*   **Component Structure**: Adhering to the **Single Responsibility Principle** by separating structural templates (HTML), specialized styling (SCSS), and component logic (TS).

### UI & UX Logic
*   **Role-Based Menu Orchestration**: Centralized configuration in `permissions.ts` that maps user roles to specific navigation sets, ensuring users only see relevant features for their role.
*   **Permission Guards**: Managing granular functional access (e.g., `canAddDietitian`) via a global `PERMISSIONS` constant.
*   **Data Visualization**: Integrated **Chart.js** via PrimeNG's `<p-chart>` to provide visual analytics (e.g., appointment distributions and patient trends).
*   **Dynamic UI Components**: Using PrimeNG's `MessageService` for global toast notifications and `DialogService` for modal-based interactions (like vitals recording).
*   **Stat Aggregation**: Implementing purely functional utility patterns to transform raw backend data into structured "Stats Cards" for Dashboards.

---

## 🔄 Integration Concepts
*   **CORS (Cross-Origin Resource Sharing)**: Configured to allow secure communication between the Angular frontend and Spring Boot backend.
*   **Mapping logic**: Frontend mapping of backend string roles (e.g., `ROLE_DIETITIAN`) into typed `Role` enums for UI consistency.
*   **Responsive Design**: Using PrimeFlex and custom SCSS to ensure the application works across all screen sizes.
