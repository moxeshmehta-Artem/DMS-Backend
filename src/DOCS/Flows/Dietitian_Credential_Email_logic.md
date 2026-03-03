# Flow Logic: User Credential Email Notification

This document details the implementation of the automatic email notification system that sends login credentials to both **Dietitians** and **Patients** upon their registration by an authorized user (Admin or Frontdesk).

---

## 🏗️ 1. Backend: Service Implementation

### Modified/New Files:
- **`pom.xml`**: Added `spring-boot-starter-mail` dependency.
- **`application.properties`**: Added SMTP configuration for Gmail.
- **`EmailService.java`**: Interface updated to support a generic `accountType`.
- **`EmailServiceImpl.java`**: Implementation customized to dynamically build subject and content based on account type.
- **`AuthServiceImpl.java`**: Integrated `EmailService` into the central registration flow.

### Logic Breakdown:

| Component               | Responsibility       | Logic / Purpose                                                                                               |
| :---------------------- | :------------------- | :------------------------------------------------------------------------------------------------------------ |
| `EmailServiceImpl.java` | Dynamic Templating   | Uses `accountType` (e.g., "Patient", "Dietitian") to generate the email subject and greeting.                 |
| `EmailServiceImpl.java` | Resilience           | Marked `JavaMailSender` as optional to allow the system to fall back to console logging in development.       |
| `EmailServiceImpl.java` | Performance          | Marked `sendCredentialsEmail` with `@Async` to make email sending non-blocking.                               |
| `AuthServiceImpl.java`  | Notification Trigger | Triggers emails for both `ROLE_DIETITIAN` (registered by Admin) and `ROLE_PATIENT` (registered by Frontdesk). |

---

## 🌐 2. Frontend Integration

### Dietitian Registration (Admin)
- **Files**: `add-dietitian.component.html/.ts`
- **Action**: Admin enters the email ID. The frontend splits the full name and passes it to the registration API.

### Patient Registration (Frontdesk/Self)
- **Files**: `registration.component.html/.ts`
- **Action**: The registration form already includes an email field. The `registerPatient` method in `AuthService` sends this along with other identity details.

---

## 📝 3. End-to-End Flow Summary

1.  **Registration**: An authorized user (Admin or Frontdesk) fills in the registration details, including a valid email address.
2.  **API Call**: The frontend sends a `SignupRequest` to `/api/auth/register`.
3.  **Persistence**: `AuthServiceImpl` saves the new user to the database.
4.  **Notification Trigger**:
    - If role is **Dietitian**: Triggers email with "Dietitian" account type.
    - If role is **Patient**: Triggers email with "Patient" account type.
5.  **Delivery**: The `EmailService` sends the email via SMTP (if configured) or logs it to the console (Mock Mode).

---

## 🛠️ Configuration Reference
Credentials are sent using the SMTP account defined in `application.properties`:
```properties
spring.mail.username=mjmehta2004@gmail.com
spring.mail.password=yfvvzfbxdzuxrsco
```
