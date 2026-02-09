# Simple JWT Authentication Code Flow

This document explains how the JWT authentication works in **simple, easy-to-understand** terms.

---

## 🎯 The Big Picture

Think of JWT authentication like a **movie ticket system**:

1. **Registration** = Creating an account at the cinema
2. **Login** = Buying a ticket (getting a JWT token)
3. **Protected Endpoints** = Showing your ticket to enter different movie halls
4. **Role** = VIP ticket vs Regular ticket (determines which halls you can enter)

---

## 📝 Flow 1: User Registration

**What happens when someone creates an account?**

```
User fills form → AuthController → AuthService → Database
    ↓                  ↓              ↓             ↓
Username: "john"   Receives      Checks if     Saves user
Email: "john@.."   request       username      with hashed
Password: "123"                  exists?       password
Role: PATIENT                    Hashes pwd
```

### Step-by-Step:

1. **User sends registration data** (username, email, password, role)
   
2. **AuthController receives it**
   - File: [AuthController.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/controllers/AuthController.java)
   - Method: [registerUser()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/controllers/AuthController.java#58-85)
   
3. **AuthController checks:**
   - Is username already taken? ❌ Return error
   - Is email already used? ❌ Return error
   
4. **AuthService hashes the password**
   - Plain password: `"password123"`
   - Hashed password: `"$2a$10$xYz...abc"` (encrypted, can't be reversed)
   
5. **Save to database**
   - User stored with hashed password
   
6. **Return success message** ✅

### Code Location:
```
AuthController.java (line ~62)
    ↓
AuthService.java (line ~40)
    ↓
Database (users table)
```

---

## 🔑 Flow 2: User Login

**What happens when someone logs in?**

```
User enters credentials → AuthController → AuthService → JwtUtils
         ↓                      ↓              ↓             ↓
Username: "john"           Receives       Checks pwd    Creates token
Password: "123"            request        matches?      with username
                                                        + role
                                          ↓
                                    Returns token to user
```

### Step-by-Step:

1. **User sends login credentials** (username, password)

2. **AuthController receives it**
   - File: [AuthController.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/controllers/AuthController.java)
   - Method: [authenticateUser()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/controllers/AuthController.java#30-57)

3. **AuthService checks the password**
   - Gets user from database by username
   - Compares entered password with hashed password
   - Uses BCrypt to check: `passwordEncoder.matches(plain, hashed)`
   
4. **If password matches:**
   - Get user's role (e.g., `ROLE_PATIENT`)
   
5. **JwtUtils creates a token**
   - Puts username in token: `"john"`
   - Puts role in token: `"ROLE_PATIENT"`
   - Sets expiration: 24 hours from now
   - Signs it with secret key (so it can't be faked)
   
6. **Return token to user** 🎫
   ```json
   {
     "token": "eyJhbGc...",
     "username": "john",
     "role": "ROLE_PATIENT"
   }
   ```

### Code Location:
```
AuthController.java (line ~28)
    ↓
AuthService.java (line ~20)
    ↓
JwtUtils.java (line ~27)
```

---

## 🛡️ Flow 3: Accessing Protected Endpoints

**What happens when someone tries to access a protected page?**

```
User makes request → JwtInterceptor → Controller
with token              ↓                 ↓
                   Checks token      Gets user info
                   Checks role       Processes request
                        ↓
                   Allow/Deny
```

### Step-by-Step:

1. **User sends request with token**
   ```
   GET /api/patients/123
   Header: Authorization: Bearer eyJhbGc...
   ```

2. **JwtInterceptor catches the request BEFORE it reaches the controller**
   - File: [JwtInterceptor.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/JwtInterceptor.java)
   - Method: [preHandle()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/JwtInterceptor.java#22-84)

3. **Interceptor checks if endpoint needs protection**
   - Looks for `@RequireRole` annotation
   - If no annotation → Let request pass ✅
   - If has annotation → Continue checking...

4. **Extract token from header**
   - Header: `"Authorization: Bearer eyJhbGc..."`
   - Extract: `"eyJhbGc..."`

5. **Validate the token**
   - Is it properly formatted? ✅
   - Is the signature valid? ✅
   - Has it expired? ❌ If yes, return 401 error
   
6. **Extract user info from token**
   - Username: `"john"`
   - Role: `"ROLE_PATIENT"`

7. **Check if user has required role**
   - Endpoint requires: `@RequireRole({"ROLE_DOCTOR", "ROLE_ADMIN"})`
   - User has: `"ROLE_PATIENT"`
   - Match? ❌ Return 403 Forbidden
   
   OR
   
   - Endpoint requires: `@RequireRole({"ROLE_PATIENT"})`
   - User has: `"ROLE_PATIENT"`
   - Match? ✅ Allow access

8. **Store user info in request**
   - `request.setAttribute("username", "john")`
   - `request.setAttribute("role", "ROLE_PATIENT")`

9. **Let request continue to controller** ✅

10. **Controller can access user info**
    ```java
    String username = (String) request.getAttribute("username");
    // username = "john"
    ```

### Code Location:
```
JwtInterceptor.java (line ~24)
    ↓
JwtUtils.java (line ~51 for validation)
    ↓
Controller method
```

---

## 🎬 Real-World Example

Let's say **Dr. Smith** wants to view patient records:

### 1️⃣ Dr. Smith Logs In
```
POST /api/auth/login
{
  "username": "dr_smith",
  "password": "doctor123"
}

Response:
{
  "token": "eyJhbGc...",
  "role": "ROLE_DOCTOR"
}
```

### 2️⃣ Dr. Smith Requests Patient Data
```
GET /api/patients/456
Header: Authorization: Bearer eyJhbGc...
```

### 3️⃣ What Happens Behind the Scenes:

```
Request arrives
    ↓
JwtInterceptor wakes up
    ↓
"Let me check this token..."
    ↓
Token is valid ✅
    ↓
"This is dr_smith with ROLE_DOCTOR"
    ↓
"Does this endpoint require a role?"
    ↓
@RequireRole({"ROLE_DOCTOR", "ROLE_ADMIN"})
    ↓
"dr_smith has ROLE_DOCTOR" ✅
    ↓
"Access granted! Passing to controller..."
    ↓
PatientController.getPatient(456)
    ↓
Returns patient data
```

### 4️⃣ If Dr. Smith Tries to Delete a User (Admin Only):
```
DELETE /api/users/789
Header: Authorization: Bearer eyJhbGc...
```

```
Request arrives
    ↓
JwtInterceptor checks
    ↓
Token valid ✅
    ↓
User: dr_smith, Role: ROLE_DOCTOR
    ↓
Endpoint requires: @RequireRole({"ROLE_ADMIN"})
    ↓
"ROLE_DOCTOR is not in [ROLE_ADMIN]" ❌
    ↓
Return 403 Forbidden
    ↓
"Access denied. Required roles: [ROLE_ADMIN]"
```

---

## 📂 File Responsibilities

### [AuthController.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/controllers/AuthController.java)
**Job:** Handle login and registration requests  
**Think of it as:** The reception desk

### [AuthService.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/service/AuthService.java)
**Job:** Check passwords, create users  
**Think of it as:** The security guard checking IDs

### [JwtUtils.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/security/jwt/JwtUtils.java)
**Job:** Create and validate tokens  
**Think of it as:** The ticket printing machine

### [JwtInterceptor.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/JwtInterceptor.java)
**Job:** Check tokens before letting requests through  
**Think of it as:** The ticket checker at the entrance

### `@RequireRole`
**Job:** Mark which endpoints need which roles  
**Think of it as:** The "VIP Only" or "Staff Only" signs

### [WebSecurityConfig.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/WebSecurityConfig.java)
**Job:** Register the interceptor  
**Think of it as:** The cinema's security policy

---

## 🔄 Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    USER REGISTRATION                        │
└─────────────────────────────────────────────────────────────┘
                           ↓
                  AuthController.registerUser()
                           ↓
                  AuthService.register()
                           ↓
                  Password gets hashed
                           ↓
                  Save to database
                           ↓
                  Return success ✅

┌─────────────────────────────────────────────────────────────┐
│                       USER LOGIN                            │
└─────────────────────────────────────────────────────────────┘
                           ↓
                  AuthController.authenticateUser()
                           ↓
                  AuthService.authenticate()
                           ↓
                  Check password matches
                           ↓
                  JwtUtils.generateToken()
                           ↓
                  Create token with username + role
                           ↓
                  Return token to user 🎫

┌─────────────────────────────────────────────────────────────┐
│                  PROTECTED ENDPOINT ACCESS                  │
└─────────────────────────────────────────────────────────────┘
                           ↓
                  Request with token arrives
                           ↓
                  JwtInterceptor.preHandle()
                           ↓
                  Extract token from header
                           ↓
                  JwtUtils.validateJwtToken()
                           ↓
                  Token valid? ─── No ──→ Return 401 ❌
                           │
                          Yes
                           ↓
                  Extract username & role
                           ↓
                  Check @RequireRole annotation
                           ↓
                  Role matches? ─── No ──→ Return 403 ❌
                           │
                          Yes
                           ↓
                  Store user info in request
                           ↓
                  Pass to controller ✅
                           ↓
                  Controller processes request
                           ↓
                  Return response
```

---

## 💡 Key Takeaways

1. **Registration** = Create account with hashed password
2. **Login** = Get a token (like a ticket)
3. **Token** = Contains username + role + expiration
4. **Interceptor** = Checks token before every protected request
5. **@RequireRole** = Specifies who can access what
6. **No token or wrong role** = Access denied

**That's it!** Simple, right? 😊
