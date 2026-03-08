# Error Handling Flow: Complete Logic Documentation

This document explains how the DMS (Dietitian Management System) handles errors gracefully across the entire stack — from the moment an exception occurrs in the Backend to the notification toast shown to the User in the Frontend.

---

## 🗺️ Overview: The Error Lifecycle

```
 ERROR OCCURS IN SERVICE
        │
        ▼
 ┌─ LAYER 1 ──── Custom Exception ───────── Thrown when business rules are broken
 │
 ├─ LAYER 2 ──── GlobalExceptionHandler ─── Catches the exception and builds a JSON response
 │
 ├─ LAYER 3 ──── REST Response (JSON) ───── Standardized error format (Status, Message, Time)
 │
 └─ LAYER 4 ──── Frontend Toast (PrimeNG) ─ Displays a red "Error" message to the user
```

---

## 🔴 LAYER 1: Custom Exceptions

Instead of using generic exceptions, we use **Custom Exceptions** to describe exactly what went wrong. These are located in `com.example.DMS_Backend.exception`.

**Examples**:
- `BookingConflictException`: Thrown if a slot is already taken.
- `UserAlreadyExistsException`: Thrown if an email is already registered.
- `VitalsMissingException`: Thrown if a dietitian tries to create a plan for a patient with no vitals.

**Why?**
Using custom exceptions allows the `GlobalExceptionHandler` to treat different problems with different HTTP status codes (e.g., 404 for Not Found, 409 for Conflict).

---

## 🟡 LAYER 2: The Global Exception Handler

**File**: `GlobalExceptionHandler.java`

This class uses the `@ControllerAdvice` annotation, which makes it a "Global Interceptor" for all controllers. It listens for exceptions and converts them into standardized JSON.

```java
@ControllerAdvice
public class GlobalExceptionHandler {

    // 1. Handling Business Logic Errors
    @ExceptionHandler(BookingConflictException.class)
    public ResponseEntity<?> handleBookingConflict(BookingConflictException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("message", ex.getMessage());
        body.put("status", HttpStatus.CONFLICT.value());
        body.put("error", "Conflict");
        return new ResponseEntity<>(body, HttpStatus.CONFLICT);
    }

    // 2. Handling Input Validation Errors (@Valid)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationErrors(MethodArgumentNotValidException ex) {
        // Collects all field errors (e.g., "Email is required") into a list
        List<Map<String, String>> details = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> {
                    Map<String, String> err = new HashMap<>();
                    err.put("field", error.getField());
                    err.put("message", error.getDefaultMessage());
                    return err;
                })
                .collect(Collectors.toList());
        
        // ... build response body with "errors" list ...
        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }

    // 3. The Catch-All (Generic Exception)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGlobalException(Exception ex) {
        // Hides technical details from the user for security
        body.put("message", "An unexpected error occurred");
        return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
```

---

## 🔵 LAYER 3: Standardized Error Response (JSON)

Every error returned by the API follows the same structure. This makes it easy for the Frontend to parse the error message.

**Example Conflict (409)**:
```json
{
  "timestamp": "2026-03-05T22:30:15",
  "status": 409,
  "error": "Conflict",
  "message": "This time slot is already booked for the selected dietitian."
}
```

**Example Validation Failure (400)**:
```json
{
  "timestamp": "2026-03-05T22:30:15",
  "status": 400,
  "error": "Validation Failed",
  "errors": [
    { "field": "email", "message": "Email must be a valid format" },
    { "field": "phone", "message": "Phone number is required" }
  ]
}
```

---

## 🟢 LAYER 4: Frontend Error Reporting

The Frontend uses PrimeNG's `MessageService` to display the error message from the backend in a red "toast" notification.

**File**: `appointment.component.ts` (Example)

```typescript
this.appointmentService.bookAppointment(payload).subscribe({
    next: (res) => {
        // Success logic
    },
    error: (err) => {
        // err.error contains the JSON from Layer 3
        const errorMessage = err.error?.message || 'Failed to book appointment';
        
        this.messageService.add({
            severity: 'error', 
            summary: 'Error', 
            detail: errorMessage // <-- User sees the "message" from the backend
        });
    }
});
```

---

## 🎯 Summary: Key Features

| Feature                 | implementation                    | Why We Use It                                                                   |
| :---------------------- | :-------------------------------- | :------------------------------------------------------------------------------ |
| **Global Interception** | `@ControllerAdvice`               | Centralizes error logic so you don't need `try-catch` in every controller.      |
| **HTTP Semantics**      | Proper Status Codes               | Uses 404, 400, 409, 500 etc. correctly according to REST standards.             |
| **Validation Mapping**  | `MethodArgumentNotValidException` | Converts complex `@Valid` errors into simple field lists for the UI.            |
| **User-Friendly**       | `MessageService` (Frontend)       | ensures the user is informed of the failure without reading technical logs.     |
| **Security**            | Masked Generic Errors             | Prevents database/logic leaks by hiding raw stack traces from the API response. |

---

## 🛠️ How to Add a New Error

1.  **Create Exception**: Create a class in `exception/` extending `RuntimeException`.
2.  **Add Handler**: Open `GlobalExceptionHandler.java` and add an `@ExceptionHandler` method for your new class.
3.  **Throw**: In your Service logic, simply write `throw new MyNewException("Helpful message");`.
4.  **UI**: The frontend will automatically receive the "Helpful message" in the `err.error.message` field.
