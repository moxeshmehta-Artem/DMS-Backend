# Database Flow & Diagrams

This document visualizes the database structure and data flow for the DMS using Mermaid diagrams.

## 1. Entity-Relationship Diagram (ERD)
This diagram shows how the tables are related to each other.

```mermaid
erDiagram
    USERS ||--o{ VITALS : "has history of"
    USERS ||--o{ APPOINTMENTS_AS_PATIENT : "books"
    USERS ||--o{ APPOINTMENTS_AS_PROVIDER : "conducts"
    USERS ||--o{ DIET_PLANS : "assigned to"
    USERS ||--o{ DIET_PLANS_AUTHOR : "created by"

    USERS {
        bigint id PK
        string username
        string role "PATIENT, DOCTOR, DIETITIAN, etc"
        string email
    }

    VITALS {
        bigint id PK
        bigint patient_id FK
        float height
        float weight
        float bmi
        datetime recorded_at
    }

    APPOINTMENTS_AS_PATIENT {
        bigint id PK
        bigint patient_id FK
        bigint provider_id FK
        datetime appointment_date
        string status "PENDING, CONFIRMED"
    }

    DIET_PLANS {
        bigint id PK
        bigint patient_id FK
        bigint assigned_by FK
        text breakfast
        text lunch
        datetime created_at
    }
```

## 2. Key Data Flows

### A. Appointment Booking Flow
How data moves when an appointment is booked and managed.

```mermaid
sequenceDiagram
    participant Patient
    participant API
    participant DB_Appointments
    participant Doctor

    Note over Patient, Doctor: Booking Phase
    Patient->>API: POST /appointments (details)
    API->>DB_Appointments: INSERT INTO appointments (status='PENDING')
    DB_Appointments-->>API: Returns Appointment ID
    API-->>Patient: Booking Confirmed (Pending)

    Note over Patient, Doctor: Approval Phase
    Doctor->>API: GET /appointments (pending)
    API->>DB_Appointments: SELECT * FROM appointments WHERE status='PENDING'
    DB_Appointments-->>Doctor: List of Requests

    Doctor->>API: PUT /appointments/{id}/status (CONFIRMED)
    API->>DB_Appointments: UPDATE appointments SET status='CONFIRMED'
    DB_Appointments-->>API: Success
    API-->>Doctor: Appointment Confirmed
```

### B. Patient Vitals Recording Flow
How health data is tracked over time.

```mermaid
graph LR
    A[Frontdesk/Nurse] -->|Inputs Vitals| B(API: POST /vitals)
    B -->|Validate & Calculate BMI| C{Valid Data?}
    C -->|Yes| D[(Database: INSERT vitals)]
    D -->|Link| E[User Record]
    C -->|No| F[Return Error]
    
    style D fill:#bbf,stroke:#333
    style E fill:#bfb,stroke:#333
```
