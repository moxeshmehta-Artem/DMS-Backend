# Why the Backend is the "Source of Truth" for Roles

The most common question in security is: *"Can a developer change their role in the browser console to become an Admin?"* 

The answer in this project is **No**. Here is the specific code flow that explains why permissions do **not** come from the frontend.

---

## 🔒 The Token is a "Sealed Envelope"

Think of the JWT token as a sealed envelope. The frontend can see what's inside, but if it tries to change anything, the seal breaks, and the Backend will reject it.

---

## 1. Login: Role Assignment (The Source)
**File**: `service/impl/AuthServiceImpl.java`

When you log in, the backend looks you up in the **Database**. It finds your real role there and "stamps" it into the token.

```java
// AuthServiceImpl.java (Line 42)
String roleString = user.getRole().name(); // Fetched from Database!
String jwt = jwtUtils.generateToken(user.getUsername(), roleString, user.getId());
```

---

## 2. Token Generation (The Seal)
**File**: `security/jwt/JwtUtils.java`

The backend takes that role and "signs" it using a **Secret Key** (from `application.properties`) that only the server knows.

```java
// JwtUtils.java (Line 32)
public String generateToken(String username, String role, Long id) {
    return Jwts.builder()
            .claims(Map.of("role", role)) // Role is put inside
            .signWith(key(), Jwts.SIG.HS256) // SIGNED with secret key
            .compact();
}
```

---

## 3. The Catch: Validation (The Check)
**File**: `config/JwtInterceptor.java`

When the frontend sends a request, it sends the "Envelope" (Token). The `JwtInterceptor` doesn't ask the frontend "what is the role?". Instead, it opens the envelope and checks the signature.

```java
// JwtInterceptor.java (Line 50)
if (jwtUtils.validateJwtToken(token)) { // Checks if the "Seal" is broken
    String role = jwtUtils.getRoleFromJwtToken(token); // Reads the "Stashed" role
    
    // Check against @RequireRole
    if (Arrays.asList(requiredRoles).contains(role)) {
        return true; // Access Granted
    }
}
```

---

## ❓ Common Questions

### "Does the frontend send any permissions?"
**No.** The frontend only sends the **Token**. The token is proof of identity, not a list of "I want permission X". The Backend decides what that token is allowed to do.

### "What if a user changes their role in LocalStorage?"
Your Angular code might see `role: 'ADMIN'` and show them the "Add Dietitian" button (UX level). However, when they click that button, they send their **old token** (which still says `ROLE_PATIENT` inside). The `JwtInterceptor` will see the conflict and block the request with a **403 Forbidden**. 

### "Where is the mapping defined?"
*   **Database**: Stores `id -> role` (The permanent truth).
*   **Backend controllers**: `@RequireRole` defines `Method -> Roles` (The access policy).
*   **Frontend permissions.ts**: Defines `Role -> UI Buttons` (The visual convenience).

---

## 🎯 Final Verdict
*   **Frontend**: Decides what the user **sees** (for a better experience).
*   **Backend**: Decides what the user **does** (for guaranteed security).
