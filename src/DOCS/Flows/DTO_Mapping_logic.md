# DTOs, Entities, and Mapping: Logic Documentation

This document explains the relationship between **Entities** (Database), **DTOs** (API/Frontend), and the **Mappers** that bridge them. It specifically focuses on how complex database relationships are converted into simple, flat data for the frontend.

---

## 🏗️ The 3-Tier Architecture

In this project, data follows this journey:

```
 DATABASE (MySQL)  <───>  ENTITY (Java)  <───>  MAPPER (MapStruct)  <───>  DTO (JSON)  <───>  FRONTEND (Angular)
```

| Component                      | Layer         | Purpose                                                                                                               | Example                    |
| :----------------------------- | :------------ | :-------------------------------------------------------------------------------------------------------------------- | :------------------------- |
| **Entity**                     | Database/JPA  | Represents a **Table** in the database. Contains sensitive data (passwords) and complex relationships (`@ManyToOne`). | `Appointment.java`         |
| **DTO** (Data Transfer Object) | API/Network   | Represents the **JSON** sent to the frontend. contains only the fields the UI needs.                                  | `AppointmentResponse.java` |
| **Mapper**                     | Logic/Utility | The "Bridge" that copies data from Entity to DTO automatically.                                                       | `AppointmentMapper.java`   |

---

## 🔍 Case Study: Appointment Mapping

Let's look at how a complex **Appointment** object is converted.

### 1. The Entity (Complex Relationships)
**File**: `Appointment.java`
The entity holds actual **User objects** for the patient and dietitian.

```java
public class Appointment extends BaseEntity {
    private Long id;
    
    @ManyToOne
    private User patient;   // ⬅️ A whole User object (with password, email, etc.)
    
    @ManyToOne
    private User dietitian; // ⬅️ Another whole User object
    
    private LocalDate appointmentDate;
    private String timeSlot;
    private AppointmentStatus status;
}
```

### 2. The DTO (Flattened for Frontend)
**File**: `AppointmentResponse.java`
The frontend doesn't need the whole User object. It just needs the **ID** and the **Name**.

```java
public class AppointmentResponse {
    private Long id;
    private Long patientId;     // ⬅️ Just the ID
    private String patientName; // ⬅️ Just the String name
    private Long providerId;    // ⬅️ dietitian ID
    private String providerName;// ⬅️ dietitian Name
    private LocalDate appointmentDate;
    private String timeSlot;
    private AppointmentStatus status;
}
```

---

## 🗺️ The Bridge: How MapStruct Converts Them

**File**: `AppointmentMapper.java`

MapStruct is an annotation processor that generates the conversion code at compile time. It uses simple rules to "flatten" the object.

```java
@Mapper(componentModel = "spring")
public interface AppointmentMapper {

    // Rule 1: Extract ID from the nested patient object
    @Mapping(target = "patientId", source = "patient.id")
    
    // Rule 2: Extract ID from the nested dietitian object
    @Mapping(target = "providerId", source = "dietitian.id")

    // Rule 3: Use a custom helper to get names
    @Mapping(target = "patientName", source = "patient", qualifiedByName = "fullName")
    @Mapping(target = "providerName", source = "dietitian", qualifiedByName = "fullName")
    
    AppointmentResponse toResponse(Appointment appointment);

    @Named("fullName")
    default String getFullName(User user) {
        // Logic to combine firstName + lastName OR use username
        return user.getFirstName() + " " + user.getLastName();
    }
}
```

---

## 💡 Why Do We Use DTOs? (Why not just send the Entity?)

1.  **Security**: Entities often contain `password` or internal `deleted` flags. DTOs ensure this sensitive data **never** leaves the server.
2.  **Performance**: Sending a whole `User` object inside an `Appointment` object creates a huge JSON. DTOs send only the 2-3 fields the UI actually uses.
3.  **Frontend Simplicity**: The frontend doesn't have to write `appointment.patient.id`. It simply uses `appointment.patientId`.
4.  **Decoupling**: You can change your Database table structure without breaking the Frontend API, as long as you update the Mapper.

---

## 🔄 The Conversion Process (Step-by-Step)

When a dietitian views their appointments:

1.  **Repository**: `List<Appointment> appts = repo.findAll();` (Fetches rows from DB).
2.  **Service**: Loops through the list and calls the Mapper.
3.  **Mapper**:
    - Takes `Appointment.patient` (User object) → Extracts `id` → Sets `DTO.patientId`.
    - Takes `Appointment.patient` → Runs `getFullName()` → Sets `DTO.patientName`.
    - Copies `date`, `slot`, and `status` directly (since field names match).
4.  **Controller**: Returns the `List<AppointmentResponse>` as JSON.

### Summary of field matches:

| Entity Field      | --- Mapping Rule --->           | DTO Field         |
| :---------------- | :------------------------------ | :---------------- |
| `id`              | Direct Match                    | `id`              |
| `patient.id`      | `@Mapping(source="patient.id")` | `patientId`       |
| `patient`         | `fullName` (Custom logic)       | `patientName`     |
| `appointmentDate` | Direct Match                    | `appointmentDate` |
| `status`          | Enum Conversion                 | `status`          |

---

## 🛠️ How to Add a New Field

1.  **Update Entity**: Add the field to the `.java` entity class (and check DB schema).
2.  **Update DTO**: Add the field to the `...Response.java` class.
3.  **Update Mapper**:
    - If field names are **identical** (e.g., `notes`): Nothing needed! MapStruct maps them automatically.
    - If names are **different** (e.g., `user.desc` -> `description`): Add a new `@Mapping` annotation.
