# API Specification

This document outlines the REST API endpoints to be implemented in the Spring Boot backend to support the DMS frontend.

**Base URL**: `/api/v1`

## 1. Authentication
| Method | Endpoint | Request Body | Response | Description |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/auth/register` | `{ username, password, email, role, firstName, lastName }` | `UserDTO` | Register a new user |
| `POST` | `/auth/login` | `{ username, password }` | `{ token, user: UserDTO }` | Login and receive JWT token |

## 2. Patients
| Method | Endpoint | Description | Roles Allowed |
| :--- | :--- | :--- | :--- |
| `GET` | `/patients` | Get all patients | ADMIN, DOCTOR, FRONTDESK, DIETITIAN |
| `GET` | `/patients/{id}` | Get specific patient details | ADMIN, DOCTOR, FRONTDESK, DIETITIAN, PATIENT (Self) |
| `POST` | `/patients` | Create a new patient profile (if separate from auth) | FRONTDESK, ADMIN |
| `PUT` | `/patients/{id}` | Update patient profile | FRONTDESK, ADMIN, PATIENT (Self) |

## 3. Vitals
| Method | Endpoint | Request Body | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/patients/{patientId}/vitals` | - | Get history of vitals for a patient |
| `POST` | `/patients/{patientId}/vitals` | `{ height, weight, bp_systolic, ... }` | Record new vitals |

## 4. Appointments
| Method | Endpoint | Request Body | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/appointments` | Query Params: `?date=...&doctorId=...&patientId=...` | Get list of appointments (filterable) |
| `POST` | `/appointments` | `{ patientId, providerId, date, timeSlot, description }` | Book a new appointment |
| `GET` | `/appointments/{id}` | - | Get appointment details |
| `PUT` | `/appointments/{id}/status` | `{ status: "CONFIRMED" | "REJECTED" | "COMPLETED" }` | Update appointment status |
| `PUT` | `/appointments/{id}/notes` | `{ notes: "..." }` | Add doctor notes |

## 5. Diet Plans
| Method | Endpoint | Request Body | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/patients/{patientId}/diet-plans` | - | Get diet plans for a patient |
| `POST` | `/patients/{patientId}/diet-plans` | `{ breakfast, lunch, dinner, snacks }` | Assign a diet plan |
| `PUT` | `/diet-plans/{id}` | `{ ... }` | Update an existing diet plan |

## 6. Doctors / Dietitians
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/providers` | Get list of all doctors and dietitians (filterable by role) |
| `GET` | `/providers/{id}/slots` | Get available time slots for a provider on a given date |

## Response Standards
**Success (200 OK / 201 Created):**
```json
{
  "status": "success",
  "data": { ... }
}
```

**Error (400/404/500):**
```json
{
  "status": "error",
  "message": "Error description here",
  "code": "ERROR_CODE"
}
```
