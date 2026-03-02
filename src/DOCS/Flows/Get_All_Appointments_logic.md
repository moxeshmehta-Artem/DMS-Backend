# Flow Logic: Get All Appointments (Front Desk Dashboard)

This document provides a line-by-line explanation of the `getAllAppointments` flow, used to power the management overview on the Front Desk Dashboard.

---

## 🏗️ 1. Backend: Retrieval & Mapping
**File**: `AppointmentServiceImpl.java` -> `getAllAppointments()`

This method retrieves every appointment record from the database for administrative oversight.

### Line-by-Line Breakdown:

| Line of Code | Explanation | Logic / Purpose |
| :--- | :--- | :--- |
| `appointmentRepository.findAll()` | Executes a `SELECT * FROM appointments` query. | **Full Data Pull**: Retrieves every record without filtering. |
| `.stream()` | Converts the list of entities into a Java Stream. | **Functional Processing**: Enables efficient mapping. |
| `.map(appointmentMapper::toResponse)` | Passes each `Appointment` entity through the Mapper. | **Data Sanitization**: Converts entities to DTOs, hides sensitive fields, and calculates names. |
| `.collect(Collectors.toList())` | Gathers the processed DTOs back into a List. | **Preparation**: Ready to be sent as a JSON array. |

---

## 🌐 2. Frontend: Dashboard Integration
**File Path**: `front-desk-dashboard.component.ts` -> `loadPatientOverview()`

The dashboard uses this data to calculate global statistics and display management charts.

### Line-by-Line Breakdown:

| Line of Code | Explanation | Logic / Purpose |
| :--- | :--- | :--- |
| `this.appointmentService.getAllAppointments().subscribe(...)` | Triggers the HTTP GET request to the backend. | **Async Data Fetch**: Waits for the server response. |
| `const totalAppointments = allAppointments.length;` | Counts the total count of all records. | **Stat Calculation**: Value for the "Total Appointments" card. |
| `allAppointments.filter(a => a.status === 'PENDING').length` | Filters and counts only the `PENDING` items. | **Stat Calculation**: Value for the "Action Required" card. |
| `allAppointments.filter(a => a.appointmentDate === today).length` | Filters and counts items scheduled for the current date. | **Stat Calculation**: Value for the "Today's Schedule" card. |
| `const charts = prepareChartData(allAppointments);` | Passes the full list to a utility to build graphs. | **Analytics**: Converts raw data into visual chart formats. |
| `this.chartData = charts.chartData;` | Updates the component property bound to the pie chart. | **UI Update**: Instant refresh of the dashboard graphs. |

---

## 📝 3. Summary of the Flow
1. **Trigger**: Front Desk staff enters the **Dashboard**.
2. **Frontend**: Request is sent to `GET /api/appointments`.
3. **Backend**: Pulls all records, converts them to DTOs, and returns them.
4. **Frontend**: Receives the array and "slices" it (filters/counts) to fill the colorful **Summary Cards** and **Analytics Charts**.
