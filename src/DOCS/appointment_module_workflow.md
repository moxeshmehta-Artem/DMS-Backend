# Appointment Module: Technical Workflow & Documentation

This document provides a comprehensive overview of the Appointment Module in the Diet Management System (DMS), covering the end-to-end workflow from patient booking to dietitian completion.

## 1. Module Overview
The Appointment Module enables:
- **Patients** to find dietitians and book slots.
- **Dietitians** to manage requests, accept/reject bookings, and create diet plans upon completion.
- **Frontdesk** to monitor overall system activity and statistics.

---

## 2. Core Data Models

### Backend Entity ([Appointment.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/models/Appointment.java))
The core object representing an appointment in the database.
```java
@Entity
@Table(name = "appointments")
public class Appointment {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne @JoinColumn(name = "patient_id")
    private User patient;

    @ManyToOne @JoinColumn(name = "dietitian_id")
    private User dietitian;

    private LocalDate appointmentDate;
    private String timeSlot;

    @Enumerated(EnumType.STRING)
    private AppointmentStatus status; // PENDING, CONFIRMED, REJECTED, COMPLETED, CANCELLED
    
    private String description;
    private String notes;
}
```

### Frontend Model ([appointment.model.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/core/models/appointment.model.ts))
```typescript
export interface Appointment {
    id: number;
    patientId: number;
    patientName: string;
    providerId: number;
    providerName: string;
    appointmentDate: string;
    timeSlot: string;
    status: AppointmentStatus;
    description?: string;
    notes?: string;
}
```

---

## 3. Initial API Triggers (Dashboard Load)

When a user logs in and views their dashboard, APIs are automatically triggered in the [ngOnInit](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/appointments/appointment.component.ts#164-167) lifecycle hook to populate the UI.

### Frontdesk Dashboard
Triggers two global calls to calculate statistics and populate the patient table.
```typescript
// front-desk-dashboard.component.ts
ngOnInit() {
    this.authService.getAllPatients().subscribe(...); // GET /api/users/patients
    this.appointmentService.getAllAppointments().subscribe(...); // GET /api/v1/appointments
}
```

### Patient Dashboard
Triggers a filtered call to show the patient's own upcoming visits.
```typescript
// patient-dashboard.component.ts
ngOnInit() {
    const user = this.authService.currentUser();
    this.appointmentService.getAppointmentsForPatient(user.id).subscribe(...); // GET /api/v1/appointments/patient/{id}
}
```

---

## 4. Workflow Implementation (User Triggers)

### Phase 1: Patient Booking (Explicit Trigger)
**Frontend ([doctor-selection.component.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/doctor-selection/doctor-selection.component.ts)):**
When the patient clicks "Confirm Booking" in the dialog:

```typescript
// Triggered on (onClick)="confirmBooking()"
confirmBooking() {
    this.appointmentService.bookAppointment({
        patientId: currentUser.id,
        providerId: this.selectedDietitian.id,
        appointmentDate: dateStr,
        timeSlot: this.bookingTime,
        description: this.description
    }).subscribe({
        next: (res) => this.messageService.add({ severity: 'success', summary: 'Confirmed' }),
        error: (err) => this.messageService.add({ severity: 'error', summary: 'Failed' })
    });
}
```

### Phase 2: Dietitian Management (Status Triggers)
**Frontend ([appointment.component.ts](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/appointments/appointment.component.ts)):**
When a dietitian clicks the "Accept" (check) or "Reject" (times) icon:

```typescript
// Triggered on (onClick)="updateStatus(appt, 'CONFIRMED')"
updateStatus(appt: Appointment, status: AppointmentStatus) {
    this.appointmentService.updateStatus(appt.id, status).subscribe({
        next: (updated) => {
            appt.status = updated.status;
            this.messageService.add({ severity: 'success', summary: status });
        }
    });
}
```

### Phase 3: Completion & Diet Plan
When a dietitian clicks "Save & Complete" after creating a plan, it triggers both a local save and a status update API call.

---

## 4. API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/appointments` | Book a new appointment request. |
| `GET` | `/api/v1/appointments` | Fetch all appointments (Admin/Frontdesk). |
| `GET` | `/api/v1/appointments/patient/{id}` | Get history for a specific patient. |
| `GET` | `/api/v1/appointments/provider/{id}` | Get schedule for a dietitian. |
| `PUT` | `/api/v1/appointments/{id}/status` | Update status (CONFIRMED, COMPLETED, etc.). |

---

## 5. Security & Constraints
- **Role Based Access**: Only Dietitians can update statuses; only Patients can create bookings.
- **Slot Integrity**: Backend service verifies [(appointmentDate, dietitian, timeSlot)](file:///home/artem/Desktop/DMS-Main/DMS/src/app/features/dashboard/components/patient-dashboard/patient-dashboard.component.ts#91-102) uniqueness for non-cancelled appointments.
- **Cascading Deletes**: If a user is removed, their appointments are automatically cleaned up via `@OnDelete(action = OnDeleteAction.CASCADE)`.
