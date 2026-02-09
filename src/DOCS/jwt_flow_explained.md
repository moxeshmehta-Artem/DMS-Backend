# JWT Authentication Flow - DMS Backend

This document explains the complete JWT authentication flow in the DMS (Diet Management System) backend with detailed code explanations.

---

## Table of Contents
1. [Overview](#overview)
2. [Architecture Components](#architecture-components)
3. [Registration Flow](#registration-flow)
4. [Login Flow](#login-flow)
5. [Protected Endpoint Access Flow](#protected-endpoint-access-flow)
6. [Code Walkthrough](#code-walkthrough)

---

## Overview

The DMS backend uses **JWT (JSON Web Token)** for stateless authentication. This means:
- No session data is stored on the server
- Each request contains a self-contained token
- The token is verified on every protected request

**Key Benefits:**
- Scalable (no server-side session storage)
- Secure (tokens are signed and can expire)
- Flexible (works across different clients - web, mobile)

---

## Architecture Components

### 1. **Models**
- [User.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/models/User.java) - User entity with username, email, password, role
- [Role.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/models/Role.java) - Enum defining user roles (PATIENT, DOCTOR, DIETITIAN, ADMIN, FRONTDESK)

### 2. **Security Layer**
- [JwtUtils.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/security/jwt/JwtUtils.java) - Generates and validates JWT tokens
- [AuthTokenFilter.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/security/jwt/AuthTokenFilter.java) - Intercepts requests to validate tokens
- [AuthEntryPointJwt.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/security/jwt/AuthEntryPointJwt.java) - Handles unauthorized access
- [UserDetailsImpl.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/security/services/UserDetailsImpl.java) - Spring Security user representation
- [UserDetailsServiceImpl.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/security/services/UserDetailsServiceImpl.java) - Loads user from database

### 3. **Configuration**
- [WebSecurityConfig.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/WebSecurityConfig.java) - Configures Spring Security

### 4. **Controllers & DTOs**
- [AuthController.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/controllers/AuthController.java) - Handles registration and login
- [LoginRequest.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/dto/request/LoginRequest.java), [SignupRequest.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/dto/request/SignupRequest.java), [JwtResponse.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/dto/response/JwtResponse.java), [MessageResponse.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/dto/response/MessageResponse.java)

---

## Registration Flow

```mermaid
sequenceDiagram
    participant Client
    participant AuthController
    participant UserRepository
    participant PasswordEncoder
    participant Database

    Client->>AuthController: POST /api/auth/register
    Note over Client,AuthController: {username, email, password, role}
    
    AuthController->>UserRepository: existsByUsername(username)
    UserRepository-->>AuthController: false
    
    AuthController->>UserRepository: existsByEmail(email)
    UserRepository-->>AuthController: false
    
    AuthController->>PasswordEncoder: encode(password)
    PasswordEncoder-->>AuthController: hashedPassword
    
    AuthController->>Database: Save User
    Database-->>AuthController: Success
    
    AuthController-->>Client: 200 OK
    Note over Client,AuthController: {message: "User registered successfully!"}
```

### Step-by-Step Code Explanation

**1. Client sends registration request:**
```json
POST /api/auth/register
{
  "username": "patient1",
  "email": "patient1@example.com",
  "password": "password123",
  "role": "ROLE_PATIENT"
}
```

**2. AuthController receives the request:**
```java
@PostMapping("/register")
public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    // Check if username already exists
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
        return ResponseEntity.badRequest()
            .body(new MessageResponse("Error: Username is already taken!"));
    }
    
    // Check if email already exists
    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
        return ResponseEntity.badRequest()
            .body(new MessageResponse("Error: Email is already in use!"));
    }
    
    // Create new user with encoded password
    User user = new User(
        signUpRequest.getUsername(),
        signUpRequest.getEmail(),
        encoder.encode(signUpRequest.getPassword()), // BCrypt hashing
        Role.valueOf(signUpRequest.getRole())
    );
    
    userRepository.save(user);
    
    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
}
```

**Key Points:**
- Password is **never stored in plain text** - it's hashed using BCrypt
- Username and email uniqueness is enforced
- Role is stored as a string enum value

---

## Login Flow

```mermaid
sequenceDiagram
    participant Client
    participant AuthController
    participant AuthenticationManager
    participant UserDetailsService
    participant Database
    participant JwtUtils

    Client->>AuthController: POST /api/auth/login
    Note over Client,AuthController: {username, password}
    
    AuthController->>AuthenticationManager: authenticate(username, password)
    AuthenticationManager->>UserDetailsService: loadUserByUsername(username)
    UserDetailsService->>Database: findByUsername(username)
    Database-->>UserDetailsService: User entity
    UserDetailsService-->>AuthenticationManager: UserDetails
    
    AuthenticationManager->>AuthenticationManager: Verify password
    AuthenticationManager-->>AuthController: Authentication object
    
    AuthController->>JwtUtils: generateJwtToken(username)
    JwtUtils-->>AuthController: JWT token
    
    AuthController-->>Client: 200 OK
    Note over Client,AuthController: {token, username, email, roles}
```

### Step-by-Step Code Explanation

**1. Client sends login request:**
```json
POST /api/auth/login
{
  "username": "patient1",
  "password": "password123"
}
```

**2. AuthController authenticates the user:**
```java
@PostMapping("/login")
public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    // Step 1: Authenticate using Spring Security
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            loginRequest.getUsername(),
            loginRequest.getPassword()
        )
    );
    
    // Step 2: Set authentication in security context
    SecurityContextHolder.getContext().setAuthentication(authentication);
    
    // Step 3: Generate JWT token
    String jwt = jwtUtils.generateJwtToken(authentication);
    
    // Step 4: Get user details
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());
    
    // Step 5: Return token and user info
    return ResponseEntity.ok(new JwtResponse(
        jwt,
        userDetails.getId(),
        userDetails.getUsername(),
        userDetails.getEmail(),
        roles
    ));
}
```

**3. JwtUtils generates the token:**
```java
public String generateJwtToken(Authentication authentication) {
    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
    
    return Jwts.builder()
        .setSubject(userPrincipal.getUsername())  // Username in token
        .setIssuedAt(new Date())                   // Current time
        .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs)) // Expiry
        .signWith(key(), SignatureAlgorithm.HS256) // Sign with secret key
        .compact();
}
```

**4. Client receives response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwYXRpZW50MSIsImlhdCI6MTcwNjYzNjEyNSwiZXhwIjoxNzA2NzIyNTI1fQ._oeBaye1dYSM94nnlzNNq27UGnGmCJcBcuyzP45zmQU",
  "type": "Bearer",
  "id": 1,
  "username": "patient1",
  "email": "patient1@example.com",
  "roles": ["ROLE_PATIENT"]
}
```

**Key Points:**
- Password verification happens automatically via Spring Security
- JWT token contains: username, issued time, expiration time
- Token is signed with a secret key (from [application.properties](file:///home/artem/Desktop/DMS-Main/DMS-Backend/target/classes/application.properties))
- Token expires after 24 hours (86400000 ms)

---

## Protected Endpoint Access Flow

```mermaid
sequenceDiagram
    participant Client
    participant AuthTokenFilter
    participant JwtUtils
    participant UserDetailsService
    participant Controller
    participant Database

    Client->>AuthTokenFilter: GET /api/patients (with JWT)
    Note over Client,AuthTokenFilter: Header: Authorization: Bearer <token>
    
    AuthTokenFilter->>AuthTokenFilter: Extract token from header
    AuthTokenFilter->>JwtUtils: validateJwtToken(token)
    JwtUtils-->>AuthTokenFilter: true
    
    AuthTokenFilter->>JwtUtils: getUserNameFromJwtToken(token)
    JwtUtils-->>AuthTokenFilter: username
    
    AuthTokenFilter->>UserDetailsService: loadUserByUsername(username)
    UserDetailsService->>Database: findByUsername(username)
    Database-->>UserDetailsService: User
    UserDetailsService-->>AuthTokenFilter: UserDetails
    
    AuthTokenFilter->>AuthTokenFilter: Set SecurityContext
    AuthTokenFilter->>Controller: Forward request
    Controller-->>Client: 200 OK (Protected data)
```

### Step-by-Step Code Explanation

**1. Client sends request with JWT:**
```http
GET /api/patients
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

**2. AuthTokenFilter intercepts the request:**
```java
@Override
protected void doFilterInternal(HttpServletRequest request, 
                                HttpServletResponse response, 
                                FilterChain filterChain) {
    try {
        // Step 1: Extract JWT from Authorization header
        String jwt = parseJwt(request);
        
        // Step 2: Validate token
        if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
            // Step 3: Get username from token
            String username = jwtUtils.getUserNameFromJwtToken(jwt);
            
            // Step 4: Load user details from database
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            // Step 5: Create authentication object
            UsernamePasswordAuthenticationToken authentication = 
                new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
                );
            
            authentication.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
            );
            
            // Step 6: Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    } catch (Exception e) {
        logger.error("Cannot set user authentication: {}", e);
    }
    
    // Step 7: Continue filter chain
    filterChain.doFilter(request, response);
}
```

**3. JwtUtils validates the token:**
```java
public boolean validateJwtToken(String authToken) {
    try {
        Jwts.parserBuilder()
            .setSigningKey(key())
            .build()
            .parse(authToken);
        return true;
    } catch (MalformedJwtException e) {
        logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
        logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
        logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
        logger.error("JWT claims string is empty: {}", e.getMessage());
    }
    return false;
}
```

**4. Extract username from token:**
```java
public String getUserNameFromJwtToken(String token) {
    return Jwts.parserBuilder()
        .setSigningKey(key())
        .build()
        .parseClaimsJws(token)
        .getBody()
        .getSubject(); // Returns username
}
```

**Key Points:**
- Filter runs **before** every request to protected endpoints
- Token is validated (signature, expiration, format)
- User is loaded from database using username from token
- Authentication is set in `SecurityContextHolder` for the request
- If token is invalid, request proceeds without authentication (will be rejected by authorization rules)

---

## Code Walkthrough

### 1. User Entity ([User.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/models/User.java))

```java
@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    private String email;
    private String password;  // Stored as BCrypt hash
    
    @Enumerated(EnumType.STRING)  // Store as "ROLE_PATIENT" not integer
    private Role role;
    
    private String firstName;
    private String lastName;
}
```

**Why `@Enumerated(EnumType.STRING)`?**
- Stores role as readable string in database
- Makes database queries and debugging easier
- More maintainable than integer codes

---

### 2. Security Configuration ([WebSecurityConfig.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/WebSecurityConfig.java))

```java
@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class WebSecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())  // Disable CSRF for stateless API
            .cors(Customizer.withDefaults())  // Enable CORS
            
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(unauthorizedHandler))  // Handle 401
            
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // No sessions
            
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()  // Public endpoints
                .requestMatchers("/api/test/**").permitAll()
                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated());  // All other endpoints require auth
        
        http.authenticationProvider(authenticationProvider());
        http.addFilterBefore(authenticationJwtTokenFilter(), 
                            UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
```

**Key Configuration Points:**
- **CSRF disabled**: Not needed for stateless JWT authentication
- **Stateless sessions**: No server-side session storage
- **Public endpoints**: `/api/auth/**` accessible without token
- **Filter order**: JWT filter runs before username/password filter

---

### 3. JWT Token Structure

A JWT token has 3 parts separated by dots:

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwYXRpZW50MSIsImlhdCI6MTcwNjYzNjEyNSwiZXhwIjoxNzA2NzIyNTI1fQ._oeBaye1dYSM94nnlzNNq27UGnGmCJcBcuyzP45zmQU
```

**Part 1 - Header (Algorithm):**
```json
{
  "alg": "HS256"
}
```

**Part 2 - Payload (Claims):**
```json
{
  "sub": "patient1",           // Subject (username)
  "iat": 1706636125,           // Issued at (timestamp)
  "exp": 1706722525            // Expiration (timestamp)
}
```

**Part 3 - Signature:**
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret_key
)
```

---

## Security Best Practices Implemented

1. **Password Hashing**: BCrypt with salt
2. **Token Expiration**: 24 hours
3. **Stateless Authentication**: No server-side sessions
4. **HTTPS Recommended**: Tokens should be transmitted over HTTPS in production
5. **Secret Key**: Stored in [application.properties](file:///home/artem/Desktop/DMS-Main/DMS-Backend/target/classes/application.properties) (should use environment variables in production)
6. **Role-Based Access**: Roles stored with user for authorization

---

## Common Scenarios

### Scenario 1: Token Expired
- Client sends request with expired token
- `JwtUtils.validateJwtToken()` throws `ExpiredJwtException`
- Filter logs error and continues without setting authentication
- Request reaches controller but is rejected (401 Unauthorized)

### Scenario 2: Invalid Token
- Client sends malformed or tampered token
- Signature verification fails
- Request rejected with 401

### Scenario 3: No Token
- Client sends request without Authorization header
- Filter skips JWT processing
- Request reaches controller but is rejected (401)

---

## Frontend Integration

**1. Store token after login:**
```typescript
// In Angular service
login(username: string, password: string) {
  return this.http.post('/api/auth/login', {username, password})
    .pipe(
      tap((response: any) => {
        localStorage.setItem('token', response.token);
        localStorage.setItem('user', JSON.stringify(response));
      })
    );
}
```

**2. Send token with every request:**
```typescript
// In HTTP Interceptor
intercept(req: HttpRequest<any>, next: HttpHandler) {
  const token = localStorage.getItem('token');
  
  if (token) {
    req = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }
  
  return next.handle(req);
}
```

**3. Handle 401 errors:**
```typescript
// In HTTP Interceptor
return next.handle(req).pipe(
  catchError((error: HttpErrorResponse) => {
    if (error.status === 401) {
      // Token expired or invalid
      localStorage.removeItem('token');
      this.router.navigate(['/login']);
    }
    return throwError(() => error);
  })
);
```

---

## Summary

The JWT authentication flow in DMS backend:

1. **Registration**: User creates account → Password hashed → Stored in database
2. **Login**: User authenticates → JWT token generated → Token returned to client
3. **Protected Access**: Client sends token → Filter validates → User authenticated → Request processed

This provides a secure, scalable, and stateless authentication system suitable for modern web and mobile applications.
