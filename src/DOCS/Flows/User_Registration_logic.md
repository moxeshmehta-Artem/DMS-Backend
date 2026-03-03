# Flow Logic: Authentication & Registration

This document provides a line-by-line breakdown of the `AuthServiceImpl.java` logic, covering both the **Login** and **Registration** flows.

---

## 🔑 1. Code Breakdown: `login()`
**File**: `AuthServiceImpl.java`

| Line Range | Code Snippet                      | Explanation                                                                 | Logic / Purpose                                                                                  |
| :--------- | :-------------------------------- | :-------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------- |
| **37**     | `findByUsername(...)`             | Looks up the user in the database by their unique username.                 | **Lookup**: Foundation for any auth check.                                                       |
| **41**     | `passwordEncoder.matches(...)`    | Compares the raw password from the user with the encoded one in the DB.     | **Verification**: Securely validates identity without storing raw passwords.                     |
| **42**     | `user.getRole().name()`           | Extracts the role assigned to the user (e.g., `ROLE_ADMIN`).                | **Authorization**: Determines what the user is allowed to do.                                    |
| **43**     | `jwtUtils.generateToken(...)`     | Generates a Signed JSON Web Token (JWT) containing the user ID and Role.    | **Session Management**: Allows the user to stay logged in without sending a password every time. |
| **45-51**  | `JwtResponse.builder()...build()` | Packages the JWT and user profile into a response for the frontend.         | **Response**: Supplies the frontend with the "Proof of Identity" (Token).                        |
| **54**     | `return Optional.empty()`         | Returns empty if any check fails (username not found or password mismatch). | **Security**: Generic failure prevents attackers from knowing *why* it failed.                   |

---

## 🏗️ 2. Code Breakdown: `registerUser()`
**File**: `AuthServiceImpl.java`

| Line Range | Code Snippet                                | Explanation                                             | Logic / Purpose                                                                      |
| :--------- | :------------------------------------------ | :------------------------------------------------------ | :----------------------------------------------------------------------------------- |
| **59-60**  | `log.info("Registration attempt...")`       | Logs the incoming request details.                      | **auditability**: Essential for tracking who is trying to join the system.           |
| **61-63**  | `if (userRepository.existsByUsername(...))` | Checks if the username is already taken.                | **Validation**: Prevents duplicate accounts with the same ID.                        |
| **65-67**  | `if (userRepository.existsByEmail(...))`    | Checks if the email is already in use.                  | **Integrity**: Ensures one email per account for password recovery/notifications.    |
| **70-72**  | `Period.between(dob, LocalDate.now())`      | Calculates the age based on the Date of Birth.          | **Transformation**: Automates data entry so the admin doesn't have to calculate age. |
| **74-85**  | `User.builder()...build()`                  | Builds a New User entity using the **Builder Pattern**. | **Safety**: Ensures the object is constructed correctly before saving.               |
| **77**     | `.password(passwordEncoder.encode(pw))`     | Encrypts the raw password.                              | **Security**: **NEVER** save plain-text passwords in the database.                   |
| **87**     | `userRepository.save(user)`                 | Persists the new user to the MySQL database.            | **Persistence**: Officially creates the account record.                              |
| **90-95**  | `if (...ROLE_DIETITIAN)`                    | Check for Dietitian-specific logic.                     | **Branching**: Triggers schedule creation and a "Dietitian" themed email.            |
| **95-99**  | `else if (...ROLE_PATIENT)`                 | Check for Patient-specific logic.                       | **Branching**: Triggers a "Patient" themed email.                                    |
| **93/97**  | `emailService.sendCredentialsEmail(...)`    | Calls the **Asynchronous** email service.               | **Communication**: Sends the credentials instantly in a background thread.           |

---

## 💡 2. Example Scenario: Registering a New Patient
Imagine a Frontdesk user is registering a new patient named **Moxes**.

1.  **Frontend**: Frontdesk enters `Email: moxes@example.com`, `Username: Moxes123`, `Password: M@x123`.
2.  **API**: The request hits `registerUser`.
3.  **Step 1**: The system verifies that `Moxes123` and `moxes@example.com` don't exist in the DB.
4.  **Step 2**: The password `M@x123` is hashed into something like `$2a$10$xyz...`.
5.  **Step 3**: The user is saved to the `users` table.
6.  **Step 4**: Since the role is `ROLE_PATIENT`, the `EmailService` is called with the "Patient" tag.
7.  **Result**: Moxes receives an email titled *"Your Patient Credentials - DMS"* while the Frontdesk sees a "Success" message instantly.

---

## ❓ 3. Why do we need this Documentation?

1.  **Onboarding**: New developers can understand the security (hashing) and logic (role-based branching) flows without reading 100 lines of code.
2.  **Debug Speed**: If a user says "I didn't get an email," a developer can check this doc to see that emails are only triggered for `ROLE_DIETITIAN` and `ROLE_PATIENT`—helping them narrow down the issue in seconds.
3.  **Security Compliance**: It serves as a record that we are following industry standards (like `BCrypt` password encoding and one-way data hashing).
4.  **Feature Clarity**: It clearly explains why `signUpRequest.getPassword()` is passed to the email service (to send the raw pw to the user) *before* it gets lost during hashing.
