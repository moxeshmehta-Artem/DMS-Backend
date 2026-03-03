# Flow Logic: Dietitian Credential Email Notification

This document details the implementation of the automatic email notification system that sends login credentials to dietitians upon their registration by an administrator.

---

## 🏗️ 1. Backend: Service Implementation

### Modified/New Files:
- **`pom.xml`**: Added `spring-boot-starter-mail` dependency.
- **`application.properties`**: Added SMTP configuration for Gmail.
- **`EmailService.java`** [NEW]: Defined the contract for sending emails.
- **`EmailServiceImpl.java`** [NEW]: Implementation using `JavaMailSender`.
- **`AuthServiceImpl.java`**: Integrated `EmailService` into the registration flow.

### Logic Breakdown:

| Component               | Responsibility       | Logic / Purpose                                                                                        |
| :---------------------- | :------------------- | :----------------------------------------------------------------------------------------------------- |
| `EmailServiceImpl.java` | Email Construction   | Formats the body with **First Name**, **Email ID**, **Username**, and **Password**.                    |
| `EmailServiceImpl.java` | Resilience           | Marked `JavaMailSender` as `@Autowired(required = false)` to allow system startup without SMTP config. |
| `EmailServiceImpl.java` | Error Handling       | Logs a **Mock Email** to the console if sending fails (e.g., in development environment).              |
| `AuthServiceImpl.java`  | Notification Trigger | Calls `emailService.sendCredentialsEmail` only when `ROLE_DIETITIAN` is saved.                         |
| `AuthServiceImpl.java`  | Password Handling    | Passes the raw password to the email service **before** encoding it for storage.                       |

---

## 🌐 2. Frontend: Admin Integration

### Modified Files:
- **`add-dietitian.component.html`**: Added "Email ID" input field.
- **`add-dietitian.component.ts`**: Updated Reactive Form and submission logic.
- **`auth.service.ts`**: Updated `registerDietitian` to accept the email from the UI.

### Logic Breakdown:

| Line of Code / Logic            | Explanation                                        | Purpose                                                        |
| :------------------------------ | :------------------------------------------------- | :------------------------------------------------------------- |
| `Validators.email`              | Applied to the email field in `dietitianForm`.     | Ensures data integrity on the client side.                     |
| `val.name.split(' ')`           | Splits the name input into First and Last names.   | Correctly populates individual fields in the registration DTO. |
| `registerDietitian(user, pass)` | Sends the `SignupRequest` to `/api/auth/register`. | Standardized auth flow for all roles.                          |

---

## 📝 3. End-to-End Flow Summary

1.  **Admin Input**: Administrator fills the "Add Dietitian" form, providing their actual professional email.
2.  **Frontend Processing**: The Angular component extracts the email and splits the full name into parts.
3.  **Auth API**: The backend receives the `SignupRequest` via `AuthController`.
4.  **Registration**: `AuthServiceImpl` creates the user, hashes their password for the DB, and saves the entity.
5.  **Notification**: Immediately after saving, `AuthServiceImpl` triggers the `EmailService`.
6.  **Email Delivery**: 
    - **In Production**: `JavaMailSender` sends a real email via Gmail's SMTP servers.
    - **In Development**: The system logs the full email content (including the password) to the server console.

---

## 🛠️ Configuration Checklist
To enable real email sending, ensure `application.properties` is configured:
```properties
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=mjmehta2004@gmail.com
spring.mail.password=yfvvzfbxdzuxrsco
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
```
