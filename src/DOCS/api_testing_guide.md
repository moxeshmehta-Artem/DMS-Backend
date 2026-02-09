# DMS API Testing Guide (JWT Authentication)

Use the following endpoints to verify the authentication system.

## 1. User Registration (`POST /api/auth/register`)

Registers a new user (Role can be `ROLE_PATIENT`, `ROLE_DOCTOR`, `ROLE_DIETITIAN`, `ROLE_ADMIN`, `ROLE_FRONTDESK`).

**Endpoint:** `http://localhost:8080/api/auth/register`
**Content-Type:** `application/json`

**Example Request Body:**
```json
{
  "username": "patient1",
  "email": "patient1@example.com",
  "password": "password123",
  "role": "ROLE_PATIENT"
}
```

**cURL Command:**
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"patient1","email":"patient1@example.com","password":"password123","role":"ROLE_PATIENT"}'
```

**Expected Response (200 OK):**
```json
{
  "message": "User registered successfully!"
}
```

---

## 2. User Login (`POST /api/auth/login`)

Authenticates a user and returns a JWT token.

**Endpoint:** `http://localhost:8080/api/auth/login`
**Content-Type:** `application/json`

**Example Request Body:**
```json
{
  "username": "patient1",
  "password": "password123"
}
```

**cURL Command:**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"patient1","password":"password123"}'
```

**Expected Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "type": "Bearer",
  "id": 1,
  "username": "patient1",
  "email": "patient1@example.com",
  "roles": [
    "ROLE_PATIENT"
  ]
}
```

---

## 3. Important Notes
- **JWT Token**: Use the `token` from the login response for all subsequent protected API calls by adding it to the `Authorization` header: `Bearer <your_token>`.
- **Roles**: Ensure the role string matches exactly (`ROLE_PATIENT`, etc.).
