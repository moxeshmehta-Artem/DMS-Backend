# JwtInterceptor: Complete Code Flow & Example

This document explains exactly how the `JwtInterceptor.java` works by tracing a single request from the Frontend to the Backend.

---

## 🎭 The Analogy: The Security Guard

Think of the **Interceptor** as a security guard standing at a door.

1.  **Request** = A visitor trying to enter a room.
2.  **JWT Token** = The visitor's ID card.
3.  **@RequireRole** = The sign on the door saying "ADMINS ONLY".
4.  **Interceptor Logic** = The guard checking the ID against the sign.

---

## 🛰️ Step-by-Step Flow Example

**Scenario**: A user logged in as a **PATIENT** tries to access the **Admin Dashboard**.

### 1. The Trigger (Frontend)
The Angular app sends an HTTP request:
- **URL**: `GET /api/users/all`
- **Header**: `Authorization: Bearer <ID_CARD_TOKEN>`

### 2. The Capture (Backend Interceptor)
Spring Boot catches the request and passes it to `JwtInterceptor.preHandle()`.

```java
// Inside JwtInterceptor.java
public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
    
    // A. Extract Token from Header
    String authHeader = request.getHeader("Authorization"); // "Bearer eyJhb..."
    String token = authHeader.substring(7);

    // B. Validate Token (Is it real?)
    if (jwtUtils.validateJwtToken(token)) {
        
        // C. Extract Identity (Who is this?)
        String role = jwtUtils.getRoleFromJwtToken(token); // Result: "ROLE_PATIENT"
        
        // D. Check the Door Sign (@RequireRole)
        RequireRole annotation = handlerMethod.getMethodAnnotation(RequireRole.class);
        String[] requiredRoles = annotation.value(); // Result: {"ROLE_ADMIN"}

        // E. The Final Decision
        if (Arrays.asList(requiredRoles).contains(role)) {
            return true; // ✅ LET THEM IN
        } else {
            response.setStatus(403); // ❌ BLOCK THEM (Forbidden)
            return false; 
        }
    }
}
```

### 3. The Result
- **Role in Token**: `ROLE_PATIENT`
- **Required by Controller**: `ROLE_ADMIN`
- **Action**: The guard sees they don't match. The visitor is sent away with a **403 Forbidden** error. The code inside `UserController.java` is **never executed**.

---

## 📊 Summary of Logic Blocks

| Block                 | What it handles                         | Why it's needed                                                |
| :-------------------- | :-------------------------------------- | :------------------------------------------------------------- |
| **Token Extraction**  | Removes "Bearer " prefix from header.   | To get the raw encrypted JWT string.                           |
| **Validation**        | Checks the digital signature.           | To prevent users from "faking" a token.                        |
| **Context Sync**      | Sets `SecurityContextHolder`.           | So `BaseEntity` knows who created/updated a record (Auditing). |
| **Role Verification** | Compares Token Role vs Annotation Role. | To enforce security policies (RBAC).                           |

---

## 🛠️ Testing the Flow

1.  Open your **Browser Console**.
2.  Try to visit a page your role isn't allowed to see.
3.  Look at the **Network Tab**.
4.  You will see a red request with Status **403 Forbidden**. 
5.  Check your **Spring Boot Console (Terminal)**; you will see the interceptor logging the rejection.
