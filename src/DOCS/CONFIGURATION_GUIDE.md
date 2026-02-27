# ⚙️ DMS-Backend Configuration Guide

The `config` folder contains the "brain" of our application's infrastructure. It handles security, data initialization, and automated tracking.

---

## 1. Security & Access Control

### 🛡️ `WebSecurityConfig.java`
**Purpose**: The central security hub.
- **CORS**: Defines that our Angular frontend (`localhost:4200`) is allowed to talk to this backend.
- **Interceptors**: Registers the `JwtInterceptor` to watch all `/api/**` paths.
- **Statelessness**: Disables CSRF and sessions because we use JWT tokens.
- **Password Encoding**: Sets up `BCrypt` for hashing user passwords.

### 🔑 `JwtInterceptor.java`
**Purpose**: The gatekeeper for every request.
1. It looks for the `Authorization: Bearer <token>` header.
2. It validates the token using `JwtUtils`.
3. **New Feature**: It synchronizes the user with Spring Security so that JPA Auditing knows who is performing the action.
4. It checks if the user has the required roles defined by `@RequireRole`.

### 🏷️ `RequireRole.java`
**Purpose**: A custom annotation.
- Instead of complex XML or long config files, you just put `@RequireRole({"ROLE_ADMIN"})` on top of a controller method to protect it.

---

## 2. Automated Tracking (Auditing)

### 🕵️ `AuditorAwareImpl.java`
**Purpose**: The "Who Am I?" service.
- When you save a record, JPA asks this class: "Who is the current user?".
- It looks into the `SecurityContextHolder` (populated by the Interceptor) and returns the username.
- If no one is logged in (like during startup), it returns `"SYSTEM"`.

### 📑 `JpaConfig.java`
**Purpose**: The "On Switch" for auditing.
- Contains `@EnableJpaAuditing`.
- Connects the standard Spring Auditing system to our `AuditorAwareImpl`.

---

## 3. Data Initialization

### 🌱 `DataSeeder.java`
**Purpose**: Ensures the database is never empty.
- Runs every time the application starts.
- Checks if the `admin`, `frontdesk`, `sarah` (dietitian), and `john` (patient) exist.
- If they are missing (e.g., first time setup), it creates them automatically with default passwords.
- It also generates default schedules for any dietitians it creates.

---

## 🚀 Why this structure?
- **Modular**: If you want to change how passwords are hashed, you only touch `WebSecurityConfig`.
- **Clean**: Controllers don't have to handle security logic; they just use the `@RequireRole` annotation.
- **Traceable**: Thanks to the Auditing config, every row in the database tells a story of who created it.
