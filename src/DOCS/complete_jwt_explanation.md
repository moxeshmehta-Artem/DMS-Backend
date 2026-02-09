# Complete JWT Authentication - Line-by-Line Code Explanation

This document explains **every line of code** in the JWT authentication system in simple terms.

---

## 📚 Table of Contents

1. [JwtInterceptor.java](#1-jwtinterceptorjava) - Token validation and role checking
2. [JwtUtils.java](#2-jwtutilsjava) - Token generation and validation
3. [AuthService.java](#3-authservicejava) - Authentication logic
4. [AuthController.java](#4-authcontrollerjava) - Login and registration endpoints
5. [WebSecurityConfig.java](#5-websecurityconfigjava) - Security configuration
6. [Complete Flow Examples](#6-complete-flow-examples)

---

## 1. JwtInterceptor.java

**Purpose:** Intercepts every request and checks if user has valid token and required role

### Line-by-Line Explanation

```java
1: package com.example.DMS_Backend.config;
```
**What it does:** This file belongs to the `config` package

```java
3: import com.example.DMS_Backend.security.jwt.JwtUtils;
4: import jakarta.servlet.http.HttpServletRequest;
5: import jakarta.servlet.http.HttpServletResponse;
6: import org.springframework.beans.factory.annotation.Autowired;
7: import org.springframework.stereotype.Component;
8: import org.springframework.web.method.HandlerMethod;
9: import org.springframework.web.servlet.HandlerInterceptor;
11: import java.util.Arrays;
```
**What it does:** Import all needed classes:
- [JwtUtils](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/security/jwt/JwtUtils.java#16-90) - To validate tokens
- `HttpServletRequest/Response` - To read request and send response
- `@Autowired` - For dependency injection
- `@Component` - To make this a Spring bean
- `HandlerMethod` - To check annotations on controller methods
- `HandlerInterceptor` - Interface for intercepting requests
- `Arrays` - To work with arrays

```java
16: @Component
17: public class JwtInterceptor implements HandlerInterceptor {
```
**What it does:**
- `@Component` - Spring creates and manages this class
- `implements HandlerInterceptor` - This class will intercept requests

```java
19: @Autowired
20: private JwtUtils jwtUtils;
```
**What it does:** Spring automatically injects [JwtUtils](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/security/jwt/JwtUtils.java#16-90) so we can use it

```java
23: public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
24:         throws Exception {
```
**What it does:** This method runs BEFORE every request reaches the controller
- Returns `true` = Allow request
- Returns `false` = Block request

```java
26: if (!(handler instanceof HandlerMethod)) {
27:     return true;
28: }
```
**What it does:** 
- Check if this is a controller method
- If NOT (like static files), allow it through

```java
30: HandlerMethod handlerMethod = (HandlerMethod) handler;
```
**What it does:** Convert to HandlerMethod so we can check annotations

```java
33: RequireRole methodAnnotation = handlerMethod.getMethodAnnotation(RequireRole.class);
34: RequireRole classAnnotation = handlerMethod.getBeanType().getAnnotation(RequireRole.class);
```
**What it does:**
- Line 33: Check if METHOD has `@RequireRole`
- Line 34: Check if CLASS has `@RequireRole`

```java
37: if (methodAnnotation == null && classAnnotation == null) {
38:     return true;
39: }
```
**What it does:** If NO `@RequireRole` found, this is a public endpoint - allow access

```java
42: String authHeader = request.getHeader("Authorization");
```
**What it does:** Get the Authorization header (contains the token)
- Example: `"Bearer eyJhbGciOiJIUzI1NiJ9..."`

```java
44: if (authHeader == null || !authHeader.startsWith("Bearer ")) {
45:     response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
46:     response.getWriter().write("{\"error\":\"Missing or invalid Authorization header\"}");
47:     return false;
48: }
```
**What it does:**
- Check if header exists and starts with "Bearer "
- If NO: Send 401 error and block request

```java
50: String token = authHeader.substring(7);
```
**What it does:** Remove "Bearer " prefix to get just the token
- `"Bearer abc123"` → `"abc123"`

```java
53: if (!jwtUtils.validateJwtToken(token)) {
54:     response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
55:     response.getWriter().write("{\"error\":\"Invalid or expired token\"}");
56:     return false;
57: }
```
**What it does:**
- Validate the token (check signature, expiration, format)
- If INVALID: Send 401 error and block request

```java
60: String username = jwtUtils.getUserNameFromJwtToken(token);
61: String role = jwtUtils.getRoleFromJwtToken(token);
```
**What it does:**
- Extract username from token (e.g., "john_doe")
- Extract role from token (e.g., "ROLE_DOCTOR")

```java
64: request.setAttribute("username", username);
65: request.setAttribute("role", role);
```
**What it does:** Store username and role in request so controller can access them

```java
68: RequireRole roleAnnotation = methodAnnotation != null ? methodAnnotation : classAnnotation;
69: String[] requiredRoles = roleAnnotation.value();
```
**What it does:**
- Line 68: Use method annotation if exists, else use class annotation
- Line 69: Get required roles from annotation

```java
71: if (requiredRoles.length > 0) {
72:     boolean hasAccess = Arrays.asList(requiredRoles).contains(role);
```
**What it does:**
- Line 71: If there are required roles
- Line 72: Check if user's role is in the list

```java
74: if (!hasAccess) {
75:     response.setStatus(HttpServletResponse.SC_FORBIDDEN);
76:     response.getWriter()
77:         .write("{\"error\":\"Access denied. Required roles: " + Arrays.toString(requiredRoles) + "\"}");
78:     return false;
79: }
```
**What it does:** If user doesn't have required role: Send 403 error and block request

```java
82: return true;
```
**What it does:** All checks passed! Allow request to continue to controller

---

## 2. JwtUtils.java

**Purpose:** Generate JWT tokens and validate them

### Line-by-Line Explanation

```java
1: package com.example.DMS_Backend.security.jwt;
```
**What it does:** This file belongs to the `security.jwt` package

```java
3: import io.jsonwebtoken.*;
4: import io.jsonwebtoken.io.Decoders;
5: import io.jsonwebtoken.security.Keys;
6: import org.slf4j.Logger;
7: import org.slf4j.LoggerFactory;
8: import org.springframework.beans.factory.annotation.Value;
9: import org.springframework.stereotype.Component;
11: import javax.crypto.SecretKey;
12: import java.util.Date;
13: import java.util.HashMap;
14: import java.util.Map;
```
**What it does:** Import JWT libraries and utilities

```java
16: @Component
17: public class JwtUtils {
```
**What it does:** Make this a Spring component

```java
18: private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
```
**What it does:** Create a logger to log errors

```java
20: @Value("${dms.app.jwtSecret}")
21: private String jwtSecret;
```
**What it does:** Read JWT secret key from [application.properties](file:///home/artem/Desktop/DMS-Main/DMS-Backend/target/classes/application.properties)

```java
23: @Value("${dms.app.jwtExpirationMs}")
24: private int jwtExpirationMs;
```
**What it does:** Read token expiration time (24 hours) from properties

```java
27: public String generateToken(String username, String role) {
```
**What it does:** Method to create a new JWT token

```java
28: Map<String, Object> claims = new HashMap<>();
29: claims.put("role", role);
```
**What it does:**
- Create a map to store custom data
- Put the user's role in the map

```java
31: return Jwts.builder()
32:     .claims(claims)
33:     .subject(username)
34:     .issuedAt(new Date())
35:     .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
36:     .signWith(key(), Jwts.SIG.HS256)
37:     .compact();
```
**What it does:**
- Line 32: Add custom claims (role)
- Line 33: Set subject (username)
- Line 34: Set issued time (now)
- Line 35: Set expiration time (now + 24 hours)
- Line 36: Sign with secret key using HS256 algorithm
- Line 37: Build the token string

**Result:** `"eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiUk9MRV9ET0NUT1Ii..."`

```java
40: private SecretKey key() {
41:     return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
42: }
```
**What it does:** Convert the secret string to a cryptographic key

```java
45: public String getUserNameFromJwtToken(String token) {
46:     return Jwts.parser()
47:         .verifyWith(key())
48:         .build()
49:         .parseSignedClaims(token)
50:         .getPayload()
51:         .getSubject();
52: }
```
**What it does:**
- Parse the token
- Verify signature with key
- Extract the subject (username)
- Return username

```java
56: public String getRoleFromJwtToken(String token) {
57:     Claims claims = Jwts.parser()
58:         .verifyWith(key())
59:         .build()
60:         .parseSignedClaims(token)
61:         .getPayload();
62:     
63:     return claims.get("role", String.class);
64: }
```
**What it does:**
- Parse the token
- Extract all claims
- Get the "role" claim
- Return role

```java
68: public boolean validateJwtToken(String authToken) {
69:     try {
70:         Jwts.parser().verifyWith(key()).build().parseSignedClaims(authToken);
71:         return true;
```
**What it does:**
- Try to parse and verify the token
- If successful, return true

```java
72:     } catch (MalformedJwtException e) {
73:         logger.error("Invalid JWT token: {}", e.getMessage());
74:     } catch (ExpiredJwtException e) {
75:         logger.error("JWT token is expired: {}", e.getMessage());
76:     } catch (UnsupportedJwtException e) {
77:         logger.error("JWT token is unsupported: {}", e.getMessage());
78:     } catch (IllegalArgumentException e) {
79:         logger.error("JWT claims string is empty: {}", e.getMessage());
80:     }
81:     return false;
```
**What it does:**
- Catch different types of errors
- Log the error
- Return false (token is invalid)

---

## 3. AuthService.java

**Purpose:** Handle authentication logic (check passwords, create users)

### Line-by-Line Explanation

```java
1: package com.example.DMS_Backend.service;
```
**What it does:** This file belongs to the `service` package

```java
3: import com.example.DMS_Backend.models.User;
4: import com.example.DMS_Backend.repositories.UserRepository;
5: import org.springframework.beans.factory.annotation.Autowired;
6: import org.springframework.security.crypto.password.PasswordEncoder;
7: import org.springframework.stereotype.Service;
9: import java.util.Optional;
```
**What it does:** Import needed classes

```java
11: @Service
12: public class AuthService {
```
**What it does:** Mark this as a service class

```java
14: @Autowired
15: private UserRepository userRepository;
```
**What it does:** Inject UserRepository to access database

```java
17: @Autowired
18: private PasswordEncoder passwordEncoder;
```
**What it does:** Inject PasswordEncoder to hash passwords

```java
23: public Optional<User> authenticate(String username, String password) {
```
**What it does:** Method to check if username and password are correct

```java
24: Optional<User> userOptional = userRepository.findByUsername(username);
```
**What it does:** Find user in database by username

```java
26: if (userOptional.isPresent()) {
27:     User user = userOptional.get();
```
**What it does:** If user found, get the user object

```java
28:     if (passwordEncoder.matches(password, user.getPassword())) {
29:         return Optional.of(user);
30:     }
31: }
```
**What it does:**
- Line 28: Check if entered password matches hashed password in database
- Line 29: If YES, return the user
- Line 31: If NO, continue

```java
33: return Optional.empty();
```
**What it does:** User not found or password wrong - return empty

```java
38: public User register(User user) {
39:     user.setPassword(passwordEncoder.encode(user.getPassword()));
40:     return userRepository.save(user);
41: }
```
**What it does:**
- Line 39: Hash the password before saving
- Line 40: Save user to database and return

```java
46: public boolean existsByUsername(String username) {
47:     return userRepository.existsByUsername(username);
48: }
```
**What it does:** Check if username already exists

```java
53: public boolean existsByEmail(String email) {
54:     return userRepository.existsByEmail(email);
55: }
```
**What it does:** Check if email already exists

---

## 4. AuthController.java

**Purpose:** Handle login and registration HTTP requests

### Line-by-Line Explanation

```java
1: package com.example.DMS_Backend.controllers;
```
**What it does:** This file belongs to the `controllers` package

```java
3: import com.example.DMS_Backend.models.Role;
4: import com.example.DMS_Backend.models.User;
5: import com.example.DMS_Backend.security.jwt.JwtUtils;
6: import com.example.DMS_Backend.service.AuthService;
7-11: import DTOs...
```
**What it does:** Import all needed classes

```java
17: @CrossOrigin(origins = "*", maxAge = 3600)
```
**What it does:** Allow requests from any frontend (CORS)

```java
18: @RestController
19: @RequestMapping("/api/auth")
```
**What it does:**
- `@RestController` - This handles HTTP requests
- `@RequestMapping` - All endpoints start with `/api/auth`

```java
22: @Autowired
23: private AuthService authService;
```
**What it does:** Inject AuthService

```java
25: @Autowired
26: private JwtUtils jwtUtils;
```
**What it does:** Inject JwtUtils

```java
28: @PostMapping("/login")
29: public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
```
**What it does:**
- `@PostMapping("/login")` - Handle POST requests to `/api/auth/login`
- `@RequestBody` - Read JSON from request body
- `@Valid` - Validate the input

```java
31: Optional<User> userOptional = authService.authenticate(
32:     loginRequest.getUsername(), 
33:     loginRequest.getPassword()
34: );
```
**What it does:** Call AuthService to check username and password

```java
36: if (userOptional.isEmpty()) {
37:     return ResponseEntity
38:         .badRequest()
39:         .body(new MessageResponse("Error: Invalid username or password!"));
40: }
```
**What it does:** If authentication failed, return error

```java
42: User user = userOptional.get();
43: String roleString = user.getRole().name();
```
**What it does:**
- Get the user object
- Get role as string (e.g., "ROLE_DOCTOR")

```java
46: String jwt = jwtUtils.generateToken(user.getUsername(), roleString);
```
**What it does:** Generate JWT token with username and role

```java
49: return ResponseEntity.ok(new JwtResponse(
50:     jwt,
51:     user.getId(),
52:     user.getUsername(),
53:     user.getEmail(),
54:     Collections.singletonList(roleString)
55: ));
```
**What it does:** Return success response with token and user info

```java
58: @PostMapping("/register")
59: public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
```
**What it does:** Handle POST requests to `/api/auth/register`

```java
61: if (authService.existsByUsername(signUpRequest.getUsername())) {
62:     return ResponseEntity
63:         .badRequest()
64:         .body(new MessageResponse("Error: Username is already taken!"));
65: }
```
**What it does:** Check if username already exists

```java
68: if (authService.existsByEmail(signUpRequest.getEmail())) {
69:     return ResponseEntity
70:         .badRequest()
71:         .body(new MessageResponse("Error: Email is already in use!"));
72: }
```
**What it does:** Check if email already exists

```java
75: User user = new User(
76:     signUpRequest.getUsername(),
77:     signUpRequest.getEmail(),
78:     signUpRequest.getPassword(),
79:     Role.valueOf(signUpRequest.getRole())
80: );
```
**What it does:** Create new User object with form data

```java
82: authService.register(user);
```
**What it does:** Save user to database (password will be hashed)

```java
84: return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
```
**What it does:** Return success message

---

## 5. WebSecurityConfig.java

**Purpose:** Configure security settings and register the JWT interceptor

### Line-by-Line Explanation

```java
1: package com.example.DMS_Backend.config;
```
**What it does:** This file belongs to the `config` package

```java
3-12: import statements...
```
**What it does:** Import Spring Security and configuration classes

```java
19: @Configuration
20: @EnableWebSecurity
21: public class WebSecurityConfig implements WebMvcConfigurer {
```
**What it does:**
- `@Configuration` - This is a configuration class
- `@EnableWebSecurity` - Enable Spring Security
- `implements WebMvcConfigurer` - To register interceptors

```java
23: @Autowired
24: private JwtInterceptor jwtInterceptor;
```
**What it does:** Inject our JWT interceptor

```java
29: @Bean
30: public PasswordEncoder passwordEncoder() {
31:     return new BCryptPasswordEncoder();
32: }
```
**What it does:** Create a password encoder bean for hashing passwords

```java
37: @Bean
38: public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
39:     http
40:         .csrf(csrf -> csrf.disable())
41:         .authorizeHttpRequests(auth -> auth
42:             .anyRequest().permitAll());
43:     
44:     return http.build();
45: }
```
**What it does:**
- Line 40: Disable CSRF (not needed for stateless JWT)
- Line 42: Allow all requests (JWT interceptor handles authentication)

```java
50: @Override
51: public void addInterceptors(InterceptorRegistry registry) {
52:     registry.addInterceptor(jwtInterceptor)
53:         .addPathPatterns("/api/**")
54:         .excludePathPatterns("/api/auth/**");
55: }
```
**What it does:**
- Line 52: Register our JWT interceptor
- Line 53: Apply to all `/api/**` endpoints
- Line 54: EXCEPT `/api/auth/**` (login/register are public)

```java
60: @Override
61: public void addCorsMappings(CorsRegistry registry) {
62:     registry.addMapping("/api/**")
63:         .allowedOrigins("*")
64:         .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
65:         .allowedHeaders("*")
66:         .maxAge(3600);
67: }
```
**What it does:** Configure CORS to allow frontend to call backend

---

## 6. Complete Flow Examples

### Example 1: User Registration

**Request:**
```json
POST /api/auth/register
{
  "username": "dr_smith",
  "email": "smith@hospital.com",
  "password": "doctor123",
  "role": "ROLE_DOCTOR"
}
```

**What Happens:**

1. **AuthController.java (Line 59)** - Receives request
2. **AuthController.java (Line 61)** - Check username exists?
   - Calls `authService.existsByUsername("dr_smith")`
   - **AuthService.java (Line 47)** - Query database
   - Returns `false` (username available)
3. **AuthController.java (Line 68)** - Check email exists?
   - Returns `false` (email available)
4. **AuthController.java (Line 75)** - Create User object
   - Username: "dr_smith"
   - Email: "smith@hospital.com"
   - Password: "doctor123" (plain text for now)
   - Role: ROLE_DOCTOR
5. **AuthController.java (Line 82)** - Call `authService.register(user)`
6. **AuthService.java (Line 39)** - Hash password
   - `"doctor123"` → `"$2a$10$xYz...abc"`
7. **AuthService.java (Line 40)** - Save to database
8. **AuthController.java (Line 84)** - Return success

**Response:**
```json
{
  "message": "User registered successfully!"
}
```

---

### Example 2: User Login

**Request:**
```json
POST /api/auth/login
{
  "username": "dr_smith",
  "password": "doctor123"
}
```

**What Happens:**

1. **AuthController.java (Line 31)** - Call `authService.authenticate()`
2. **AuthService.java (Line 24)** - Find user by username
   - Query database: `SELECT * FROM users WHERE username = 'dr_smith'`
   - User found ✅
3. **AuthService.java (Line 28)** - Check password
   - Compare `"doctor123"` with `"$2a$10$xYz...abc"`
   - Using BCrypt: `passwordEncoder.matches()`
   - Match ✅
4. **AuthService.java (Line 29)** - Return user
5. **AuthController.java (Line 43)** - Get role: `"ROLE_DOCTOR"`
6. **AuthController.java (Line 46)** - Generate token
7. **JwtUtils.java (Line 28-29)** - Create claims map with role
8. **JwtUtils.java (Line 31-37)** - Build token:
   - Subject: "dr_smith"
   - Role: "ROLE_DOCTOR"
   - Issued: 2026-02-09 23:00:00
   - Expires: 2026-02-10 23:00:00 (24 hours later)
   - Sign with secret key
9. **AuthController.java (Line 49)** - Return response

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiUk9MRV9ET0NUT1Ii...",
  "type": "Bearer",
  "id": 5,
  "username": "dr_smith",
  "email": "smith@hospital.com",
  "roles": ["ROLE_DOCTOR"]
}
```

---

### Example 3: Accessing Protected Endpoint

**Request:**
```
GET /api/patients/123
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

**Controller:**
```java
@GetMapping("/{id}")
@RequireRole({"ROLE_DOCTOR", "ROLE_ADMIN"})
public ResponseEntity<?> getPatient(@PathVariable Long id) {
    // ...
}
```

**What Happens:**

1. **Request arrives** at Spring Boot
2. **WebSecurityConfig.java (Line 52)** - Interceptor registered
3. **JwtInterceptor.java (Line 23)** - [preHandle()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/JwtInterceptor.java#22-84) called
4. **JwtInterceptor.java (Line 26)** - Is controller method? YES ✅
5. **JwtInterceptor.java (Line 33)** - Check for `@RequireRole`
   - Found: `@RequireRole({"ROLE_DOCTOR", "ROLE_ADMIN"})`
6. **JwtInterceptor.java (Line 37)** - Has annotation? YES (continue checking)
7. **JwtInterceptor.java (Line 42)** - Get Authorization header
   - `"Bearer eyJhbGciOiJIUzI1NiJ9..."`
8. **JwtInterceptor.java (Line 44)** - Header valid? YES ✅
9. **JwtInterceptor.java (Line 50)** - Extract token
   - `"eyJhbGciOiJIUzI1NiJ9..."`
10. **JwtInterceptor.java (Line 53)** - Validate token
11. **JwtUtils.java (Line 70)** - Parse and verify
    - Signature valid? ✅
    - Not expired? ✅
    - Format correct? ✅
12. **JwtUtils.java (Line 71)** - Return `true`
13. **JwtInterceptor.java (Line 60-61)** - Extract info
14. **JwtUtils.java (Line 46-51)** - Get username: `"dr_smith"`
15. **JwtUtils.java (Line 57-63)** - Get role: `"ROLE_DOCTOR"`
16. **JwtInterceptor.java (Line 64-65)** - Store in request
    - `request.setAttribute("username", "dr_smith")`
    - `request.setAttribute("role", "ROLE_DOCTOR")`
17. **JwtInterceptor.java (Line 69)** - Get required roles
    - `["ROLE_DOCTOR", "ROLE_ADMIN"]`
18. **JwtInterceptor.java (Line 72)** - Check if `"ROLE_DOCTOR"` in list
    - YES ✅ `hasAccess = true`
19. **JwtInterceptor.java (Line 82)** - Return `true`
20. **Request continues to controller** 🎉
21. **Controller executes** and returns patient data

**Response:**
```json
{
  "id": 123,
  "name": "John Doe",
  "age": 45,
  ...
}
```

---

### Example 4: Access Denied (Wrong Role)

**Request:**
```
DELETE /api/users/456
Authorization: Bearer eyJhbGc... (ROLE_DOCTOR token)
```

**Controller:**
```java
@DeleteMapping("/{id}")
@RequireRole({"ROLE_ADMIN"})  // Only admin can delete users
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    // ...
}
```

**What Happens:**

1-16. **Same as Example 3** (token validation passes)
17. **JwtInterceptor.java (Line 69)** - Get required roles
    - `["ROLE_ADMIN"]`
18. **JwtInterceptor.java (Line 72)** - Check if `"ROLE_DOCTOR"` in list
    - NO ❌ `hasAccess = false`
19. **JwtInterceptor.java (Line 74)** - Access denied!
20. **JwtInterceptor.java (Line 75)** - Set status 403
21. **JwtInterceptor.java (Line 76-77)** - Send error message
22. **JwtInterceptor.java (Line 78)** - Return `false`
23. **Request BLOCKED** ⛔ - Controller never runs

**Response:**
```json
{
  "error": "Access denied. Required roles: [ROLE_ADMIN]"
}
```
**Status:** 403 Forbidden

---

## 🎯 Summary

### File Responsibilities

| File | Purpose | Key Methods |
|------|---------|-------------|
| **JwtInterceptor** | Check token & role before request | [preHandle()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/JwtInterceptor.java#22-84) |
| **JwtUtils** | Create & validate tokens | [generateToken()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/security/jwt/JwtUtils.java#26-41), [validateJwtToken()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/security/jwt/JwtUtils.java#71-89) |
| **AuthService** | Check passwords, create users | [authenticate()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/service/AuthService.java#20-40), [register()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/service/AuthService.java#41-52) |
| **AuthController** | Handle login/register requests | [authenticateUser()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/controllers/AuthController.java#30-57), [registerUser()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/controllers/AuthController.java#58-85) |
| **WebSecurityConfig** | Register interceptor, configure security | [addInterceptors()](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/WebSecurityConfig.java#49-58) |

### Request Flow

```
1. User sends request
   ↓
2. WebSecurityConfig - Routes to interceptor
   ↓
3. JwtInterceptor - Validates token & checks role
   ↓
4. Controller - Processes request (if allowed)
   ↓
5. Response sent back to user
```

### Key Concepts

- **Token** = Like a ticket that proves who you are
- **Role** = What you're allowed to do (DOCTOR, ADMIN, etc.)
- **Interceptor** = Security guard checking tickets
- **@RequireRole** = Sign saying "VIP Only" or "Staff Only"

That's everything! 🎉
