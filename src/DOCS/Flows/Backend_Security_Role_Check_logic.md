# End-to-End Role-Based Security: Frontend to Backend Flow

This document explains how the system ensures that a User (e.g., a Patient) cannot access data belonging to another role (e.g., a Dietitian). It tracks the "Security Token" from the browser all the way to the Controller method.

---

## 🗺️ Overview: The Security Handshake

```
 1. FRONTEND (Browser)         2. NETWORK        3. BACKEND (Spring Boot)
 ┌───────────────────────┐   ┌─────────────┐   ┌───────────────────────────┐
 │ AuthInterceptor.ts    │──▶│ HTTP Header │──▶│ JwtInterceptor.java       │
 │ (Adds Bearer Token)   │   │             │   │ (Validates & Checks Role) │
 └───────────────────────┘   └─────────────┘   └─────────────┬─────────────┘
                                                             │
                                                             ▼
                                               4. CONTROLLER (@RequireRole)
                                               ┌───────────────────────────┐
                                               │ Blocks access if role     │
                                               │ doesn't match annotation. │
                                               └───────────────────────────┘
```

---

## 🔵 Step 1: Frontend (The "Passport" Attachment)

**File**: `core/auth/auth.interceptor.ts`

Every time the Angular app makes an API call (e.g., `GET /api/appointments`), an **Interceptor** automatically catches the request and attaches the JWT token from the browser's storage.

```typescript
// auth.interceptor.ts
const token = authService.getToken();
if (token) {
    // Clone the request and add the "Authorization" header
    const authReq = req.clone({
        setHeaders: { Authorization: `Bearer ${token}` }
    });
    return next(authReq);
}
```

---

## 🟡 Step 2: The Network (The "Secure Message")

The request travels over the internet with a header that looks like this:
`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`

Inside that encrypted string is your **Role** (e.g., `ROLE_PATIENT`).

---

## 🟢 Step 3: Backend Interception (The "Guard")

**File**: `config/JwtInterceptor.java`

Before the request reaches your Controller, Spring Boot's `JwtInterceptor` catches it. It does 3 critical things:

1.  **Validation**: Is the token real? Is it expired?
2.  **Extraction**: It extracts the `username` and `role` from the token.
3.  **Context**: It puts the user's role into Spring’s `SecurityContextHolder`. This is like putting the user's ID card on the desk so the rest of the application knows who they are.

```java
// JwtInterceptor.java
if (jwtUtils.validateJwtToken(token)) {
    String role = jwtUtils.getRoleFromJwtToken(token);
    
    // Put the role in the "Authentication" object
    UsernamePasswordAuthenticationToken auth = 
        new UsernamePasswordAuthenticationToken(username, null, List.of(new SimpleGrantedAuthority(role)));
    
    SecurityContextHolder.getContext().setAuthentication(auth);
}
```

---

## 🔴 Step 4: Method Authorization (The "Final Check")

**File**: `controllers/AppointmentController.java` (Example)

Finally, the request reaches the controller. We use the custom `@RequireRole` annotation to restrict access.

```java
@RestController
@RequestMapping("/api/appointments")
public class AppointmentController {

    @PostMapping("/book")
    @RequireRole({ "ROLE_PATIENT", "ROLE_FRONTDESK" }) // 🛡️ ONLY these roles can enter
    public ResponseEntity<?> bookAppointment(...) {
        // ... logic ...
    }
}
```

### How `@RequireRole` catches it:
Back in `JwtInterceptor.java` (Line 65), there is a specific check:
1.  It looks for the `@RequireRole` annotation on the method you are trying to call.
2.  It pulls the `requiredRoles` array from the annotation (e.g., `["ROLE_PATIENT"]`).
3.  It checks if the `role` we found in the token matches any of the `requiredRoles`.
4.  If **No Match**: It returns **403 Forbidden** immediately. The service code is never executed.

---

## 🎯 Summary: Key Connection Points

| Component           | Role           | Why it's Secure                                                     |
| :------------------ | :------------- | :------------------------------------------------------------------ |
| **JWT Token**       | The Evidence   | Digitally signed by the server. Cannot be faked by the user.        |
| **AuthInterceptor** | The Automator  | Ensures no request is "forgotten" or sent without identity.         |
| **JwtInterceptor**  | The Gatekeeper | Centralized logic. You cannot "bypass" it to reach a controller.    |
| **@RequireRole**    | The Policy     | Declares exactly which person is allowed at each specific endpoint. |

### 🛠️ Example Flow:
1.  **User** (Role: `PATIENT`) tries to `DELETE /api/users/5`.
2.  **Frontend** sends the token.
3.  **Interceptor** sees the token is valid for a `PATIENT`.
4.  **Interceptor** checks the controller: `@RequireRole("ROLE_ADMIN")`.
5.  **Result**: `PATIENT` != `ADMIN`. Access Denied (**403 Forbidden**).
