# Flow Logic: Update Appointment Status

This document explains the **`updateStatus`** workflow, which is the primary mechanism for dietitians and staff to manage the life cycle of an appointment (Approve, Reject, or Complete).

---

## 🏗️ 1. Backend: Service Execution
**File**: `AppointmentServiceImpl.java` -> `updateStatus(...)`

This method safely transitions an appointment from one state to another in the database.

### Line-by-Line Breakdown:

| Line of Code | Explanation | Logic / Purpose |
| :--- | :--- | :--- |
| `@Transactional` | Wraps the method in a database transaction. | **Data Safety**: If any part fails, the DB rolls back to the old status. |
| `appointmentRepository.findById(id)` | Fetches the record from the `appointments` table. | **Verification**: Ensures the appointment exists before changing it. |
| `appointment.setStatus(status)` | Updates the status field in the Java object. | **State Transition**: e.g., `PENDING` -> `CONFIRMED`. |
| `if (notes != null) { ... }` | Checks if the user provided any additional text. | **Communication**: Stores reasons for rejection or visit summaries. |
| `appointmentRepository.save(...)` | Commits the changes to the SQL database. | **Persistence**: Makes the change permanent. |
| `appointmentMapper.toResponse(...)` | Converts the updated record to a clean DTO. | **Response**: Sends the fresh data back to the frontend. |

---

## 🌐 2. Frontend: UI Action
**File**: `dietitian-dashboard.component.ts` -> `updateStatus(...)`

This code runs when a dietitian clicks an action button (like "Approve") on their dashboard.

### Line-by-Line Breakdown:

| Line of Code | Explanation | Logic / Purpose |
| :--- | :--- | :--- |
| `this.appointmentService.updateStatus(...)` | Calls the Angular service to send a **PUT** request. | **API Trigger**: Starts the backend process. |
| `next: (updated) => { ... }` | Success Case logic. | **Confirmation**: Runs after the backend confirms the change. |
| `this.messageService.add(...)` | Displays a popup toast to the dietitian. | **UX Feedback**: Shows "Confirmed successfully" or "Appointment rejected". |
| `if (status === 'COMPLETED' \|\| ...)` | Checks if the appointment is no longer "Active". | **List Management**: Decides if the card should stay on the screen. |
| `this.activeAppointments.filter(...)` | Removes the card from the dashboard list. | **UI Cleanup**: Instantly clears finished work from the dietitian's view. |
| `appt.status = updated.status;` | Updates the card status in-place if it stays on screen. | **State Sync**: Changes the tag color (e.g., from orange to green). |

---

## 📝 3. End-to-End Example
1. **Scenario**: A dietitian sees a `PENDING` request for 10:00 AM. They click **Approve**.
2. **Frontend**: Sends `PUT /api/appointments/5/status?status=CONFIRMED`.
3. **Backend**:
    - Finds Appointment #5.
    - Sets status to `CONFIRMED`.
    - Saves to DB.
4. **Frontend**: Receives the update, shows a green success message, and turns the tag on the dashboard from **Pending** (Orange) to **Confirmed** (Green).
