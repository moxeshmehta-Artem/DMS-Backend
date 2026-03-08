but # Backend @RequireRole Process: Detailed Code Flow

This document explains the internal machinery of the `@RequireRole` system. It shows how a simple annotation on a method transforms into a complex security check during an API call.

---

## 🏗️ The 3 Pillars of Backend Security

The system is built on three specific files:

| Component         | File                     | Responsibility                                         |
| :---------------- | :----------------------- | :----------------------------------------------------- |
| **1. The Marker** | `RequireRole.java`       | Defines the `@RequireRole` annotation.                 |
| **2. The Engine** | `JwtInterceptor.java`    | The logic that reads the annotation and blocks access. |
| **3. The Wiring** | `WebSecurityConfig.java` | Registers the Interceptor so Spring actually runs it.  |

---

## 🔴 Step 1: The Marker (The Annotation)

**File**: `config/RequireRole.java`

This is a **Custom Annotation**. We define it so we can "tag" our controller methods.

```java
@Target({ ElementType.METHOD, ElementType.TYPE }) // Can be used on methods or whole classes
@Retention(RetentionPolicy.RUNTIME)              // Must be visible while the app is running
public @interface RequireRole {
    String[] value() default {};                 // Allows us to pass roles like {"ROLE_ADMIN"}
}
```

---

## 🟡 Step 2: The Wiring (Registration)

**File**: `config/WebSecurityConfig.java`

Spring Boot doesn't know about our `JwtInterceptor` automatically. we have to tell Spring to "plug it in" to the request pipeline.

```java
@Configuration
public class WebSecurityConfig implements WebMvcConfigurer {
    
    @Autowired
    private JwtInterceptor jwtInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // This line tells Spring: "For every single URL request, run my interceptor logic first"
        registry.addInterceptor(jwtInterceptor);
    }
}
```

---

## 🟢 Step 3: The Engine (The Interceptor Logic)

**File**: `config/JwtInterceptor.java`

This is where the magic happens. When a request for `/api/appointments` comes in, this class is triggered **before** the controller.

### 1. Identify the Target
It first checks if the thing you are trying to visit is actually a Controller method.
```java
HandlerMethod handlerMethod = (HandlerMethod) handler;
RequireRole methodAnnotation = handlerMethod.getMethodAnnotation(RequireRole.class);
```

### 2. Verify the Role
If the annotation is present, it looks at the **JWT Token** you sent from the frontend.

```java
// Extract role from token
String userRole = jwtUtils.getRoleFromJwtToken(token); 

// Extract required roles from the @RequireRole annotation
String[] requiredRoles = methodAnnotation.value(); 

// The Final Decision
boolean hasAccess = Arrays.asList(requiredRoles).contains(userRole);

if (!hasAccess) {
    response.setStatus(403); // Forbidden!
    return false;            // Stop the request here.
}
```

---

## 🔵 Step 4: The Usage (The Controller)

**File**: `controllers/UserController.java`

Now, you can protect any method simply by adding the tag.

```java
@GetMapping("/all")
@RequireRole("ROLE_ADMIN") // 🛡️ The Interceptor will now protect this method.
public List<User> getAllUsers() {
    return userService.findAll();
}
```

---

## 🔄 Summary: The Chain Reaction

1.  **Server Starts**: `WebSecurityConfig` registers the `JwtInterceptor`.
2.  **Request Hits Server**: Spring looks at its "Interceptor Registry" and sees `JwtInterceptor`.
3.  **Interceptor Runs**:
    - It sees the user is a `ROLE_PATIENT`.
    - It sees the target method needs `ROLE_ADMIN`.
    - It sees they don't match.
4.  **Action**: It sends a **403 Forbidden** response back to the browser.
5.  **Stop**: The `userService.findAll()` method is **never even called**. This protects your data and your server resources.

---

## 💡 Benefits of this Custom Approach
*   **Lightweight**: We don't need the massive "Spring Security" dependency for simple role checks.
*   **Flexible**: You can put `@RequireRole` on a whole class to protect every method inside it at once. 
*   **Zero-Effort**: Once the Interceptor is set up, adding security to a new feature takes exactly 1 second (adding the annotation).
