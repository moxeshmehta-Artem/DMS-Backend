# Authentication System: Technical Walkthrough (TL Presentation)

## Purpose
This document provides a technical deep-dive into the **User Registration and Login** modules of the Diet Management System (DMS). It includes specific code references (with line numbers) to facilitate a code walkthrough with technical stakeholders.

---

## 1. Process Flow: Patient Registration

### Step 1: Frontend - Service Call
When the user submits the registration form, `AuthService.registerPatient()` is called. It constructs the payload with the critical `ROLE_PATIENT` string.

> **File**: [DMS/src/app/core/auth/auth.service.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/auth/auth.service.ts)
```typescript
93:     registerPatient(userModel: User, password: string): Observable<any> {
94:         const signupRequest: SignupRequest = {
95:             username: userModel.username,
96:             email: userModel.email || '', // Ensure email is present
97:             password: password,
98:             role: 'ROLE_PATIENT', // <--- IMPORTANT: Explicit checks against Backend Enum
99:             firstName: userModel.firstName,
100:            lastName: userModel.lastName
101:        };
102:        console.log('Registering Patient with payload:', signupRequest);
103:        // ...
106:        return this.register(signupRequest);
107:    }
```

### Step 2: Backend - Controller Entry Point
The request hits the [AuthController](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/controllers/AuthController.java#15-49). The `@Valid` annotation triggers DTO validation (checking `@NotBlank`, `@Email` constraints).

> **File**: `DMS-Backend/.../controllers/AuthController.java`
```java
37:         @PostMapping("/register")
38:         public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
39:                 try {
40:                         authService.registerUser(signUpRequest);
41:                         return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
42:                 } catch (RuntimeException e) {
                            // ... error handling
46:                 }
47:         }
```

### Step 3: Backend - Business Logic & Persistence
The service checks for existing users, encrypts the password, and saves the entity. We use Lombok's Builder pattern here.

> **File**: `DMS-Backend/.../service/AuthService.java`
```java
60:     public void registerUser(SignupRequest signUpRequest) {
61:         if (userRepository.existsByUsername(signUpRequest.getUsername())) { ... }
65:         if (userRepository.existsByEmail(signUpRequest.getEmail())) { ... }
69:         // Create new user's account with Builder
70:         User user = User.builder()
71:                 .username(signUpRequest.getUsername())
                    // ...
73:                 .password(passwordEncoder.encode(signUpRequest.getPassword()))
74:                 .role(Role.valueOf(signUpRequest.getRole())) // Parses "ROLE_PATIENT"
75:                 .firstName(signUpRequest.getFirstName())
76:                 .lastName(signUpRequest.getLastName())
77:                 .build();
79:         userRepository.save(user);
80:     }
```

---

## 2. Process Flow: User Login

### Step 1: Frontend - Component Logic
The [LoginComponent](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/auth/login/login.component.ts#6-95) calls the service.

> **File**: [DMS/src/app/features/auth/login/login.component.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/auth/login/login.component.ts)
```typescript
75:   onLogin() {
76:     this.loginError = false;
77:     if (this.username && this.password) {
78:       this.isLoading = true;
80:       this.authService.login({ username: this.username, password: this.password })
81:         .subscribe({
82:           next: () => {
83:             this.router.navigate(['/dashboard']);
                // ...
85:           },
              // ...
91:         });
92:     }
93:   }
```

### Step 2: Backend - Authentication & Token Generation
The backend verifies the password hash and generates a signed JWT.

> **File**: `DMS-Backend/.../service/AuthService.java`
```java
33:     public Optional<JwtResponse> login(LoginRequest loginRequest) {
34:         Optional<User> userOptional = userRepository.findByUsername(loginRequest.getUsername());
36:         if (userOptional.isPresent()) {
37:             User user = userOptional.get();
39:             if (passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
41:                 String roleString = user.getRole().name();
42:                 String jwt = jwtUtils.generateToken(user.getUsername(), roleString);
44:                 return Optional.of(JwtResponse.builder()
45:                         .token(jwt)
                            // ...
49:                         .roles(Collections.singletonList(roleString))
50:                         .build());
51:             }
52:         }
53:         return Optional.empty();
54:     }
```

---

## 3. The "Glue": JWT Interceptor (Every Request)

Once the user has a token, it must be sent with every request (e.g., to fetch Appointments).

> **File**: [DMS/src/app/core/auth/auth.interceptor.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/auth/auth.interceptor.ts)
```typescript
5: export const authInterceptor: HttpInterceptorFn = (req, next) => {
6:     const authService = inject(AuthService);
7:     const token = authService.getToken();
9:     if (token) {
10:         const cloned = req.clone({
11:             headers: req.headers.set('Authorization', `Bearer ${token}`)
12:         });
13:         return next(cloned); // Proceed with Token
14:     }
16:     return next(req); // Proceed without Token (if public)
17: };
```

---

## 4. Key Improvements Summary
*   **Resolved Role Enum Mismatch**: Explicit mapping in `AuthService.ts` (Line 98) ensures frontend sends `ROLE_PATIENT` correctly.
*   **Reduced Boilerplate**: Implemented Lombok `@Builder` in backend models ([User.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/models/User.java), [AuthService.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/service/AuthService.java) Lines 70-77).
*   **Enhanced Data Capture**: Updated Backend [AuthService](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/auth/auth.service.ts#34-210) (Line 75-76) to capture First/Last names during registration.
