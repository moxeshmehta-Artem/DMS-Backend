# Email Notification Flow: Complete Logic Documentation

This document explains how the Email Notification system works in the DMS (Dietitian Management System). It covers everything from configuration and asynchronous processing to the fail-safe mechanisms for development.

---

## 🗺️ Overview: The Email Flow

```
 CLIENT REGISTRATION (Patient/Dietitian)
        │
        ▼
 ┌─ LAYER 1 ──── AuthServiceImpl ────────── Triggers email after successful DB save
 │
 ├─ LAYER 2 ──── EmailServiceImpl (@Async) ─ Prepares and sends email in a background thread
 │
 ├─ LAYER 3 ──── application.properties ─── Stores SMTP (Gmail) credentials
 │
 └─ LAYER 4 ──── Gmail SMTP Server ──────── Delivers the email to the user
```

---

## 🔵 LAYER 1: Trigger (Authentication Service)

**File**: `AuthServiceImpl.java`

When a new user is registered, the system triggers an email containing their auto-generated credentials.

```java
// Inside registerPatient or registerDietitian method
String password = generateRandomPassword(); // Example
user.setPassword(passwordEncoder.encode(password));
userRepository.save(user);

// SEND EMAIL (Non-blocking)
emailService.sendCredentialsEmail(
    user.getEmail(), 
    user.getFirstName(), 
    user.getUsername(), 
    password, 
    "PATIENT" // or "DIETITIAN"
);
```

**Why here?**
We send the email only **after** the user is successfully saved in the database.

---

## 🟢 LAYER 2: The Service implementation (Asynchronous)

**File**: `EmailServiceImpl.java`

This layer is responsible for translating the request into a formatted email message and sending it using JavaMail.

```java
@Service
@Slf4j
public class EmailServiceImpl implements EmailService {

    @Autowired(required = false)
    private JavaMailSender mailSender;

    @Override
    @Async // ⚡ ASYNCHRONOUS - This is CRITICAL
    public void sendCredentialsEmail(String to, String firstName, String username, String password, String accountType) {
        log.info("Preparing to send {} credentials email to: {}", accountType, to);
        
        String subject = String.format("Your %s Credentials - DMS", accountType);
        String content = String.format(
                "Hello %s,\n\n" +
                "Your %s account has been created successfully.\n\n" +
                "Email ID: %s\n" +
                "Username: %s\n" +
                "Password: %s\n\n",
                firstName, accountType.toLowerCase(), to, username, password);

        try {
            if (mailSender == null) {
                throw new IllegalStateException("JavaMailSender is not configured.");
            }
            
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject(subject);
            message.setText(content);
            
            mailSender.send(message); // Actually sends the mail

            log.info("Credentials email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send email to: {}. Error: {}", to, e.getMessage());
            
            // 🛡️ FAIL-SAFE / MOCK (Invaluable for local development)
            log.warn("MOCK EMAIL [DEVELOPMENT]:\nTo: {}\nSubject: {}\nContent: \n{}", to, subject, content);
        }
    }
}
```

### Why `@Async`?
Sending an email involves a network call to the SMTP server (Gmail). This can take 2–5 seconds. If we sent it synchronously, the **Registration button would hang** for several seconds, providing a poor user experience. 

By using `@Async`, the `AuthServiceImpl` returns immediately to the user, and the email is sent in a **background thread**.

**Note**: To enable this, the main class `DmsBackendApplication.java` must have the `@EnableAsync` annotation.

---

## 🟡 LAYER 3: Configuration (SMTP)

**File**: `application.properties`

The system connects to Gmail's SMTP server using the following credentials:

```properties
# SMTP Configuration (Gmail Example)
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=mjmehta2004@gmail.com
spring.mail.password=yfvvzfbxdzuxrsco  # Gmail App Password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
```

**Why Gmail App Password?**
Modern email providers like Gmail don't allow sign-in with a normal password via code for security reasons. Instead, you generate a **16-character App Password** to use in your `application.properties`.

---

## 🛡️ Development & Troubleshooting (Mock Mode)

In a local development environment, you might not have internet access or your SMTP credentials might be wrong. The system handles this gracefully:

1.  **The Error is Caught**: The `try-catch` block prevents the whole registration from failing just because the email failed.
2.  **Terminal Log**: Instead of an actual email, the credentials are printed clearly in the **Spring Boot console**.
3.  **Trace**: You can simply look at your terminal to see the auto-generated password for testing.

---

## 🎯 Summary: key Features

| Feature                    | implementation           | Why We Use It                                                                           |
| :------------------------- | :----------------------- | :-------------------------------------------------------------------------------------- |
| **Separation of Concerns** | `EmailService` interface | Decouples registration logic from mail sending logic.                                   |
| **Performance**            | `@Async`                 | Prevents registration UI from freezing during the network call.                         |
| **Error Handling**         | `try-catch`              | Ensures user registration succeeds even if the email service is down.                   |
| **Fail-safe**              | Mock Logging             | Allows developers to see credentials during testing even without a working mail server. |
| **Security**               | Gmail App Password       | Uses encrypted TLS (Port 587) for secure delivery.                                      |

---

## 🧪 Testing the Flow

1.  Register a new patient via the **Admin Dashboard** or **Front Desk**.
2.  Open your **Backend Terminal**.
3.  Look for the `log.info` output:
    - If successful: `Credentials email sent successfully to: user@example.com`
    - If failed: `MOCK EMAIL [DEVELOPMENT]: To: user@example.com Content: ...`
