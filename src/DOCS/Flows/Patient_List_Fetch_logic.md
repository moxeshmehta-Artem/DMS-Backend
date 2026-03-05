# Patient List Fetch: Complete HTML → Database Code Flow

This document explains **every single piece of code** involved when the Front Desk Dashboard loads the patient list — from the HTML the user sees, all the way down to the SQL that hits the database.

---

## 🗺️ Overview: The 8 Layers

```
 USER CLICKS DASHBOARD
        │
        ▼
 ┌─ LAYER 1 ──── HTML Template ──────────────── What the user SEES
 │
 ├─ LAYER 2 ──── Angular Component (.ts) ────── TRIGGERS the data fetch
 │
 ├─ LAYER 3 ──── Angular Service (.ts) ──────── SENDS the HTTP request
 │
 │               ~~~~~~~~~~~~~ NETWORK ~~~~~~~~~~~~~
 │
 ├─ LAYER 4 ──── Spring Controller (.java) ──── RECEIVES the HTTP request
 │
 ├─ LAYER 5 ──── Spring Service (.java) ─────── BUSINESS LOGIC (batch queries)
 │
 ├─ LAYER 6 ──── MapStruct Mapper (.java) ───── CONVERTS Entity → DTO
 │
 ├─ LAYER 7 ──── Spring Repository (.java) ──── GENERATES SQL queries
 │
 └─ LAYER 8 ──── MySQL Database ─────────────── STORES & RETURNS raw data
```

---

---

## 🟢 LAYER 1: HTML Template (What the User Sees)

**File**: `front-desk-dashboard.component.html`

### 1A. Stats Cards (Top of the page)
```html
<div class="col-12 md:col-6 lg:col-3" *ngFor="let card of statsCards">
    <div class="surface-card shadow-2 p-3 border-round ...">
        <span class="block text-500 font-medium mb-3">{{ card.label }}</span>
        <div class="text-900 font-medium text-4xl">{{ card.value }}</div>
    </div>
</div>
```

**Why?** → `*ngFor` loops over `statsCards` array and renders 4 cards: Total Patients, Appointments, Pending, Today's.

### 1B. Patient Table (Main content)
```html
<app-registered-patients [patients]="patientOverview"
    (onRegister)="navigateTo('/registration')"
    (onAddVitals)="onAddVitals($event)">
</app-registered-patients>
```

**Why?** → This is a **reusable child component**. Instead of writing the table HTML here, we pass the `patientOverview` data into a separate component via `[patients]` input binding. This keeps code organized and reusable.

### 1C. Inside `registered-patients.component.html` (The actual table)
```html
<p-table #dt [value]="patients" [paginator]="true" [rows]="5"
    [globalFilterFields]="['firstName','lastName','username','phone']">

    <!-- Table Header -->
    <ng-template pTemplate="header">
        <tr>
            <th pSortableColumn="firstName">Name</th>
            <th>Age</th>
            <th>Gender</th>
            <th>Contact</th>
            <th>Latest Appointment</th>
            <th>Status</th>
            <th>Actions</th>
        </tr>
    </ng-template>

    <!-- Each Patient Row -->
    <ng-template pTemplate="body" let-patient>
        <tr>
            <td>
                <div class="font-medium">{{ patient.firstName }} {{ patient.lastName }}</div>
                <small class="text-500">{{ patient.username }}</small>
            </td>
            <td>{{ patient.age || 0 }} yrs</td>
            <td>{{ patient.gender }}</td>
            <td>{{ patient.phone }}</td>
            <td>
                <!-- Shows date if appointment exists, otherwise shows "-" -->
                <div *ngIf="patient.latestAppointment">
                    {{ patient.latestAppointment.date | date:'shortDate' }}
                </div>
                <span *ngIf="!patient.latestAppointment">-</span>
            </td>
            <td>
                <!-- Color-coded status badge -->
                <p-tag *ngIf="patient.latestAppointment"
                    [severity]="patient.latestAppointment.status | statusSeverity"
                    [value]="patient.latestAppointment.status">
                </p-tag>
            </td>
            <td>
                <!-- Shows "Add Vitals" if no vitals, "Edit Vitals" if vitals exist -->
                <button *ngIf="!patient.vitals" pButton label="Add Vitals"
                    (click)="onAddVitals.emit(patient.id)"></button>
                <button *ngIf="patient.vitals" pButton label="Edit Vitals"
                    (click)="onAddVitals.emit(patient.id)"></button>
            </td>
        </tr>
    </ng-template>
</p-table>
```

**Why each piece?**

| HTML Code                          | Why We Use It                                                                  |
| :--------------------------------- | :----------------------------------------------------------------------------- |
| `<p-table [value]="patients">`     | PrimeNG table component — provides built-in sorting, pagination, and filtering |
| `[paginator]="true" [rows]="5"`    | Shows 5 patients per page to avoid long scrolling                              |
| `[globalFilterFields]`             | Enables the search box to filter by name, username, or phone                   |
| `{{ patient.firstName }}`          | **Bound to `PatientResponse.firstName`** from the backend                      |
| `patient.latestAppointment.date`   | **Bound to `LatestAppointmentResponse.date`** — batch-fetched                  |
| `patient.latestAppointment.status` | Shows PENDING/CONFIRMED/COMPLETED as a color tag                               |
| `*ngIf="!patient.vitals"`          | Decides whether to show "Add" or "Edit" button based on whether vitals exist   |

**Example**: When the table renders, each `patient` object looks like this:
```json
{
  "firstName": "Artem",
  "lastName": "Kumar",
  "age": 28,
  "gender": "Male",
  "phone": "9876543210",
  "vitals": { "height": 175, "weight": 72 },
  "latestAppointment": { "date": "2026-03-05", "status": "CONFIRMED" }
}
```

---

## 🟡 LAYER 2: Angular Component (Triggers the Fetch)

**File**: `front-desk-dashboard.component.ts`

### Class Setup
```typescript
export class FrontDeskDashboardComponent implements OnInit {
    private userService = inject(UserService);
    private appointmentService = inject(AppointmentService);

    patientOverview: any[] = [];   // ← Data for the patient table
    statsCards: any[] = [];        // ← Data for the 4 stat cards

    ngOnInit() {
        this.loadPatientOverview();  // ← Called when page loads
    }
}
```

**Why `inject()`?** → This is Angular's modern dependency injection. Instead of the older constructor-based injection, `inject()` is cleaner and works well with standalone components.

**Why `OnInit`?** → `ngOnInit()` runs after the component is created. We fetch data here (not in the constructor) because the component needs to be fully initialized first.

### The Main Method: `loadPatientOverview()`
```typescript
loadPatientOverview() {
    // STEP 1: Fetch all patients (with vitals + appointments embedded)
    this.userService.getAllPatients().subscribe({
        next: (patients) => {

            // STEP 2: Also fetch ALL appointments (for stats + charts)
            this.appointmentService.getAllAppointments().subscribe({
                next: (allAppointments) => {

                    // STEP 3: Calculate Stats
                    const totalPatients = patients.length;
                    const totalAppointments = allAppointments.length;
                    const pendingAppointments = allAppointments
                        .filter(a => a.status === 'PENDING').length;

                    const today = new Date().toISOString().split('T')[0];
                    const todaysAppointments = allAppointments
                        .filter(a => a.appointmentDate === today).length;

                    // STEP 4: Populate the 4 stat cards
                    this.statsCards = [
                        { label: 'Total Patients', value: totalPatients, ... },
                        { label: 'Appointments', value: totalAppointments, ... },
                        { label: 'Pending', value: pendingAppointments, ... },
                        { label: "Today's", value: todaysAppointments, ... }
                    ];

                    // STEP 5: Prepare chart data
                    const charts = prepareChartData(allAppointments);
                    this.chartData = charts.chartData;

                    // STEP 6: Set patient data for the table
                    this.patientOverview = patients.map((patient: any) => ({
                        ...patient,
                        latestAppointment: patient.latestAppointment || null
                    }));
                }
            });
        }
    });
}
```

**Why each step?**

| Step | Code                                          | Why                                                                                                            |
| :--- | :-------------------------------------------- | :------------------------------------------------------------------------------------------------------------- |
| 1    | `userService.getAllPatients().subscribe(...)` | **Subscribe** to the Observable to trigger the HTTP request. Without `.subscribe()`, the request is never sent |
| 2    | Nested `getAllAppointments()`                 | Stats cards need appointment counts (total, pending, today)                                                    |
| 3    | `.filter(a => a.status === 'PENDING').length` | Count how many appointments need action                                                                        |
| 4    | `this.statsCards = [...]`                     | Feeds the `*ngFor` in the HTML that renders the 4 cards                                                        |
| 5    | `prepareChartData()`                          | Transforms raw appointments into chart-ready data for PrimeNG charts                                           |
| 6    | `this.patientOverview = patients.map(...)`    | Passes data to `<app-registered-patients>` which renders the table                                             |

---

## 🟠 LAYER 3: Angular Service (Sends HTTP Request)

**File**: `user.service.ts`

```typescript
@Injectable({ providedIn: 'root' })
export class UserService {
    private readonly API_URL = 'http://localhost:8080/api/users';
    private http = inject(HttpClient);

    getAllPatients(): Observable<User[]> {
        return this.http.get<any[]>(`${this.API_URL}/patients`).pipe(
            map(users => users.map(u => ({
                ...this.mapToUser(u),
                role: Role.Patient
            })))
        );
    }

    private mapToUser(u: any): User {
        return {
            id: u.id,
            username: u.username,
            firstName: u.firstName,
            lastName: u.lastName,
            gender: u.gender,
            email: u.email,
            phone: u.phone,
            age: u.age,
            vitals: u.vitals,               // ← From backend's batch fetch
            latestAppointment: u.latestAppointment,  // ← From backend's batch fetch
            role: this.mapBackendRoleToEnum([u.role || 'ROLE_PATIENT']),
            permissions: [],
            token: ''
        };
    }
}
```

**Why each piece?**

| Code                                  | Why We Use It                                                              |
| :------------------------------------ | :------------------------------------------------------------------------- |
| `@Injectable({ providedIn: 'root' })` | Makes this service a **singleton** — one instance shared by the entire app |
| `HttpClient`                          | Angular's built-in HTTP client for making REST API calls                   |
| `this.http.get<any[]>(...)`           | Sends a **GET** request to `http://localhost:8080/api/users/patients`      |
| `.pipe(map(...))`                     | Transforms the raw JSON response into typed `User[]` objects               |
| `...this.mapToUser(u)`                | Spread operator: copies all mapped fields into the new object              |
| `role: Role.Patient`                  | Hardcodes the role since we know this endpoint only returns patients       |

**What gets sent over the network:**
```
GET http://localhost:8080/api/users/patients
Headers: Authorization: Bearer <JWT_TOKEN>
```

---

## 🔴 LAYER 4: Spring Controller (Receives the Request)

**File**: `UserController.java`

```java
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/patients")
    @RequireRole({ "ROLE_ADMIN", "ROLE_FRONTDESK", "ROLE_DIETITIAN" })
    public ResponseEntity<List<PatientResponse>> getAllPatients() {
        return ResponseEntity.ok(userService.getAllPatients());
    }
}
```

**Why each annotation?**

| Annotation/Code                 | Why We Use It                                                                       | Example                                          |
| :------------------------------ | :---------------------------------------------------------------------------------- | :----------------------------------------------- |
| `@RestController`               | Tells Spring this class handles HTTP requests and returns JSON automatically        | Without it, Spring won't know to handle requests |
| `@RequestMapping("/api/users")` | **Base URL prefix** — all endpoints here start with `/api/users`                    | `/api/users/patients`, `/api/users/{id}`         |
| `@RequiredArgsConstructor`      | Lombok generates a constructor that injects `UserService` automatically             | Replaces `@Autowired` — cleaner approach         |
| `@GetMapping("/patients")`      | Maps `GET /api/users/patients` to this method                                       | Combined with base: `/api/users` + `/patients`   |
| `@RequireRole(...)`             | **Custom security annotation** — only Admin, Frontdesk, and Dietitian can call this | A patient can NOT call this endpoint             |
| `ResponseEntity.ok(...)`        | Wraps the response in a `200 OK` HTTP status                                        | Returns `{ status: 200, body: [...] }`           |

**What `@RequireRole` does** (from `RequireRole.java`):
```java
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireRole {
    String[] value() default {};
}
```
This is a **custom annotation** that works with a JWT filter interceptor. Before `getAllPatients()` runs, the system extracts the user's role from their JWT token and checks if it matches one of the allowed roles. If not → **403 Forbidden**.

---

## 🟣 LAYER 5: Service Layer (The Heart — Business Logic)

**File**: `UserServiceImpl.java`

```java
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final AppointmentRepository appointmentRepository;
    private final VitalsService vitalsService;
    private final PatientMapper patientMapper;

    @Override
    public List<PatientResponse> getAllPatients() {

        // ══════════════════════════════════════════════
        //  QUERY 1: Get all patients from the users table
        // ══════════════════════════════════════════════
        List<User> patients = userRepository.findByRole(Role.ROLE_PATIENT);
        // SQL: SELECT * FROM users WHERE role = 'ROLE_PATIENT' AND deleted = false
        // Example result: [User(id=12, "Artem"), User(id=13, "Priya"), User(id=14, "Raj")]

        // ══════════════════════════════════════════════
        //  QUERY 2: Batch fetch latest vitals for ALL patients
        // ══════════════════════════════════════════════
        List<VitalsResponse> allLatestVitals = vitalsService
                .getLatestVitalsForPatients(patients);
        // Returns: [VitalsResponse(patientId=12, height=175, weight=72), ...]

        Map<Long, VitalsResponse> vitalsMap = allLatestVitals.stream()
                .collect(Collectors.toMap(VitalsResponse::getPatientId, v -> v));
        // Converts List → Map for O(1) lookup:
        // { 12 → VitalsResponse(175, 72), 13 → VitalsResponse(160, 55) }

        // ══════════════════════════════════════════════
        //  QUERY 3: Batch fetch latest appointments for ALL patients
        // ══════════════════════════════════════════════
        List<Appointment> allLatestAppts = appointmentRepository
                .findLatestAppointmentsByPatients(patients);
        // Returns the most recent appointment for each patient

        Map<Long, LatestAppointmentResponse> apptMap = allLatestAppts.stream()
                .collect(Collectors.toMap(
                        a -> a.getPatient().getId(),     // Key: patient ID
                        a -> LatestAppointmentResponse.builder()
                                .id(a.getId())            // Appointment ID
                                .date(a.getAppointmentDate())  // e.g., 2026-03-05
                                .status(a.getStatus())    // e.g., CONFIRMED
                                .build(),
                        (existing, replacement) -> existing  // If duplicate, keep first
                ));
        // Result: { 12 → LatestAppt(id=42, CONFIRMED), 14 → LatestAppt(id=38, PENDING) }

        // ══════════════════════════════════════════════
        //  ASSEMBLY: Stitch everything together
        // ══════════════════════════════════════════════
        return patients.stream().map(user -> {
            PatientResponse res = patientMapper.toResponse(user);  // Map basic fields
            res.setVitals(vitalsMap.get(user.getId()));             // Attach vitals
            res.setLatestAppointment(apptMap.get(user.getId()));   // Attach appointment
            return res;
        }).collect(Collectors.toList());
    }
}
```

**Why each piece?**

| Code                                                   | Why We Use It                                                                                                                                |
| :----------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------- |
| `@Service`                                             | Marks this as a Spring-managed service bean                                                                                                  |
| `implements UserService`                               | Follows **Interface Segregation** — controller depends on the interface, not the implementation. This allows swapping implementations easily |
| `@RequiredArgsConstructor`                             | Lombok generates constructor injection for all `final` fields — cleaner than `@Autowired`                                                    |
| `findByRole(Role.ROLE_PATIENT)`                        | **1 query** instead of fetching all users and filtering in Java                                                                              |
| `vitalsService.getLatestVitalsForPatients(patients)`   | **Batch fetch** — 1 query for ALL patients' vitals, not N individual queries                                                                 |
| `Collectors.toMap(...)`                                | Converts `List` → `Map<patientId, data>` so we can look up each patient's vitals/appointments in **O(1)** time instead of looping            |
| `(existing, replacement) -> existing`                  | **Merge function** — if 2 appointments map to the same patient (shouldn't happen with MAX query, but safety), keep the first                 |
| `patientMapper.toResponse(user)`                       | Maps `User` entity → `PatientResponse` DTO (auto-generated by MapStruct)                                                                     |
| `res.setVitals(...)` / `res.setLatestAppointment(...)` | Manually sets the fields that MapStruct intentionally **ignores**                                                                            |

### Why 3 Batch Queries? (N+1 Problem Prevention)

**Bad approach (N+1)** — If we had 50 patients:
```
1 query:  Get 50 patients
50 queries: Get vitals for patient 1, patient 2, ... patient 50
50 queries: Get appointment for patient 1, ... patient 50
= 101 database queries ❌
```

**Our approach (Batch):**
```
1 query: Get 50 patients
1 query: Get vitals for ALL 50 patients at once
1 query: Get appointments for ALL 50 patients at once
= 3 database queries ✅
```

---

## 🔵 LAYER 6: MapStruct Mapper (Entity → DTO Conversion)

**File**: `PatientMapper.java`

```java
@Mapper(componentModel = "spring")
public interface PatientMapper {
    @Mapping(target = "vitals", ignore = true)
    @Mapping(target = "latestAppointment", ignore = true)
    @Mapping(target = "age", source = "age")
    PatientResponse toResponse(User user);
}
```

**Why we use a Mapper:**

| Without Mapper (Manual)                                          | With MapStruct Mapper                                           |
| :--------------------------------------------------------------- | :-------------------------------------------------------------- |
| You write 10+ lines of `dto.setFirstName(entity.getFirstName())` | MapStruct generates this code **automatically at compile time** |
| Error-prone — easy to forget a field                             | All matching fields are auto-mapped                             |
| Manual maintenance when fields change                            | Regenerates when you rebuild                                    |

**What `@Mapping` does:**

| Annotation                                              | Effect                                            | Why                                                                                 |
| :------------------------------------------------------ | :------------------------------------------------ | :---------------------------------------------------------------------------------- |
| `@Mapping(target = "vitals", ignore = true)`            | Does NOT map `vitals` from User → PatientResponse | Because the `User` entity doesn't have vitals — we set this manually in the service |
| `@Mapping(target = "latestAppointment", ignore = true)` | Does NOT map `latestAppointment`                  | Same reason — set manually from batch query                                         |
| `@Mapping(target = "age", source = "age")`              | Explicitly maps `age`                             | Even though it could auto-map, being explicit avoids ambiguity                      |

**What MapStruct generates** (in `PatientMapperImpl.java`):
```java
// AUTO-GENERATED — you never write this manually
public class PatientMapperImpl implements PatientMapper {
    @Override
    public PatientResponse toResponse(User user) {
        return PatientResponse.builder()
            .id(user.getId())
            .username(user.getUsername())
            .firstName(user.getFirstName())
            .lastName(user.getLastName())
            .gender(user.getGender())
            .email(user.getEmail())
            .age(user.getAge())
            .phone(user.getPhone())
            // vitals → NOT set (ignored)
            // latestAppointment → NOT set (ignored)
            .build();
    }
}
```

---

## 🟤 LAYER 7: Repositories (Generate SQL Queries)

### 7A. `UserRepository.java` — Query 1
```java
public interface UserRepository extends JpaRepository<User, Long> {
    List<User> findByRole(Role role);
}
```

**Why?** → Spring Data JPA reads the method name `findByRole` and **auto-generates** the SQL:
```sql
SELECT * FROM users WHERE role = 'ROLE_PATIENT' AND deleted = false;
```
The `AND deleted = false` part is auto-added by `@SQLRestriction("deleted = false")` on the `User` entity (soft delete filter).

### 7B. `VitalsRepository.java` — Query 2
```java
public interface VitalsRepository extends JpaRepository<Vitals, Long> {

    @Query("SELECT v FROM Vitals v WHERE v.deleted = false AND v.id IN " +
           "(SELECT MAX(v2.id) FROM Vitals v2 WHERE v2.patient IN :patients " +
           "AND v2.deleted = false GROUP BY v2.patient)")
    List<Vitals> findLatestVitalsByPatients(@Param("patients") List<User> patients);
}
```

**Why a custom `@Query`?** → This SQL is too complex for method naming. It needs a subquery.

**The SQL explained step by step:**
```sql
-- Inner query: Find the ID of the LATEST vitals record for each patient
SELECT MAX(v2.id) FROM vitals v2
WHERE v2.patient_id IN (12, 13, 14)    -- Our 3 patients
  AND v2.deleted = false
GROUP BY v2.patient_id;
-- Result: (45, 38, 52) → Latest vitals IDs

-- Outer query: Fetch the full vitals rows for those IDs
SELECT * FROM vitals v
WHERE v.deleted = false
  AND v.id IN (45, 38, 52);
-- Result: 3 Vitals objects (one per patient)
```

### 7C. `AppointmentRepository.java` — Query 3
```java
public interface AppointmentRepository extends JpaRepository<Appointment, Long> {

    @Query("SELECT a FROM Appointment a WHERE a.deleted = false AND a.id IN " +
           "(SELECT MAX(a2.id) FROM Appointment a2 WHERE a2.patient IN :patients " +
           "AND a2.deleted = false GROUP BY a2.patient)")
    List<Appointment> findLatestAppointmentsByPatients(
            @Param("patients") List<User> patients);
}
```

**Why?** → Same pattern as vitals. `MAX(a2.id)` finds the most recent appointment per patient.

```sql
-- For patients [12, 13, 14]:
-- Patient 12 has appointments: id=35, id=42 → MAX = 42
-- Patient 13 has no appointments → not in result
-- Patient 14 has appointments: id=38 → MAX = 38
-- Result: Appointment(42, "2026-03-05", CONFIRMED), Appointment(38, "2026-03-01", PENDING)
```

---

## ⚫ LAYER 8: Database Tables & Entity Classes

### 8A. `User` Entity (maps to `users` table)
```java
@Entity
@SQLRestriction("deleted = false")    // ← Auto-filters soft-deleted records
@Table(name = "users", uniqueConstraints = {
    @UniqueConstraint(columnNames = "username"),
    @UniqueConstraint(columnNames = "email")
})
public class User extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String email;
    private String password;      // ← In DB, but NEVER sent to frontend (mapper skips it)
    private String gender;
    private int age;
    private String firstName;
    private String lastName;
    private String phone;

    @Enumerated(EnumType.STRING)
    private Role role;            // ← ROLE_PATIENT, ROLE_DIETITIAN, etc.
}
```

**Why each annotation?**

| Annotation                           | Why                                                                                                          |
| :----------------------------------- | :----------------------------------------------------------------------------------------------------------- |
| `@Entity`                            | Tells JPA this class maps to a database table                                                                |
| `@SQLRestriction("deleted = false")` | **Soft delete** — every query automatically adds `WHERE deleted = false`, so "deleted" records are invisible |
| `@Table(name = "users")`             | Maps to the `users` table (explicit name)                                                                    |
| `@UniqueConstraint`                  | Database-level guarantee that no two users have the same username or email                                   |
| `@Id @GeneratedValue`                | Auto-incrementing primary key                                                                                |
| `@Enumerated(EnumType.STRING)`       | Stores role as text `"ROLE_PATIENT"` not as a number                                                         |
| `extends BaseEntity`                 | Inherits audit fields (see below)                                                                            |

### 8B. `BaseEntity` (Inherited audit fields)
```java
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity {

    @CreatedDate
    private LocalDateTime createdAt;      // Auto-set when record is created

    @LastModifiedDate
    private LocalDateTime updatedAt;      // Auto-updated on every save

    @CreatedBy
    private String createdBy;             // Username from JWT token

    @LastModifiedBy
    private String lastModifiedBy;        // Username from JWT token

    private boolean deleted = false;      // Soft delete flag
    private LocalDateTime deletedAt;      // When it was soft-deleted
}
```

**Why?** → Every entity (`User`, `Appointment`, `Vitals`) extends this, so they all automatically get:
- **Audit trail** — who created/modified the record and when
- **Soft delete** — records are never physically deleted, just marked `deleted = true`

### 8C. `PatientResponse` DTO (What goes back to frontend)
```java
@Data
@Builder
public class PatientResponse {
    private Long id;
    private String username;
    private String gender;
    private String email;
    private String firstName;
    private String lastName;
    private int age;
    private String phone;
    private VitalsResponse vitals;                    // ← Set manually in service
    private LatestAppointmentResponse latestAppointment;  // ← Set manually in service
}
```

**Why a separate DTO?** → The `User` entity has `password`, `createdBy`, `deleted`, etc. We **never** want to send those to the frontend. The DTO contains only the fields the UI needs.

### 8D. `VitalsResponse` DTO
```java
public class VitalsResponse {
    private Long id;
    private Long patientId;
    private Double height;
    private Double weight;
    private Double bmi;
    private Double bpSystolic;
    private Double bpDiastolic;
    private Integer heartRate;
    private Double temperature;
    private LocalDateTime recordedAt;
}
```

### 8E. `LatestAppointmentResponse` DTO
```java
public class LatestAppointmentResponse {
    private Long id;
    private LocalDate date;
    private AppointmentStatus status;  // PENDING, CONFIRMED, COMPLETED, etc.
}
```

---

## 📝 Complete Example: Following One Request

Let's trace a real request for a database with **3 patients**:

### Step 1: User opens Front Desk Dashboard
```
Browser → GET http://localhost:8080/api/users/patients
Header: Authorization: Bearer eyJhbGciOi...
```

### Step 2: Controller receives, checks role → calls service

### Step 3: Service runs 3 SQL queries

**Query 1** — Get all patients:
```sql
SELECT * FROM users WHERE role = 'ROLE_PATIENT' AND deleted = false;
```
| id  | username | firstName | lastName | age | password    |
| --- | -------- | --------- | -------- | --- | ----------- |
| 12  | artem_p  | Artem     | Kumar    | 28  | $2a$10$x... |
| 13  | priya_s  | Priya     | Sharma   | 32  | $2a$10$y... |
| 14  | raj_m    | Raj       | Mehta    | 45  | $2a$10$z... |

**Query 2** — Get latest vitals:
```sql
SELECT * FROM vitals WHERE id IN (SELECT MAX(id) FROM vitals
    WHERE patient_id IN (12,13,14) AND deleted = false GROUP BY patient_id);
```
| id  | patient_id | height | weight | bmi  |
| --- | ---------- | ------ | ------ | ---- |
| 45  | 12         | 175    | 72     | 23.5 |
| 52  | 14         | 170    | 85     | 29.4 |

> Note: Patient 13 (Priya) has NO vitals → "Add Vitals" button will show

**Query 3** — Get latest appointments:
```sql
SELECT * FROM appointments WHERE id IN (SELECT MAX(id) FROM appointments
    WHERE patient_id IN (12,13,14) AND deleted = false GROUP BY patient_id);
```
| id  | patient_id | date       | status    |
| --- | ---------- | ---------- | --------- |
| 42  | 12         | 2026-03-05 | CONFIRMED |
| 38  | 14         | 2026-03-01 | PENDING   |

### Step 4: Service assembles response

```java
// For patient Artem (id=12):
PatientResponse {
    id: 12,
    firstName: "Artem",          // From Query 1 (User table)
    vitals: { height: 175, ... }, // From Query 2 (Vitals table)
    latestAppointment: { date: "2026-03-05", status: "CONFIRMED" }  // From Query 3
}
// Note: password is NOT included — mapper doesn't map it
```

### Step 5: JSON response sent to frontend
```json
[
    {
        "id": 12,
        "username": "artem_p",
        "firstName": "Artem",
        "lastName": "Kumar",
        "age": 28,
        "gender": "Male",
        "phone": "9876543210",
        "vitals": { "height": 175, "weight": 72, "bmi": 23.5 },
        "latestAppointment": { "id": 42, "date": "2026-03-05", "status": "CONFIRMED" }
    },
    {
        "id": 13,
        "username": "priya_s",
        "firstName": "Priya",
        "lastName": "Sharma",
        "age": 32,
        "vitals": null,
        "latestAppointment": null
    },
    {
        "id": 14,
        "username": "raj_m",
        "firstName": "Raj",
        "lastName": "Mehta",
        "age": 45,
        "vitals": { "height": 170, "weight": 85, "bmi": 29.4 },
        "latestAppointment": { "id": 38, "date": "2026-03-01", "status": "PENDING" }
    }
]
```

### Step 6: Table renders

| Name         | Age    | Latest Appointment | Status      | Actions     |
| ------------ | ------ | ------------------ | ----------- | ----------- |
| Artem Kumar  | 28 yrs | 3/5/26             | ✅ CONFIRMED | Edit Vitals |
| Priya Sharma | 32 yrs | -                  |             | Add Vitals  |
| Raj Mehta    | 45 yrs | 3/1/26             | ⏳ PENDING   | Edit Vitals |

---

## 🎯 Summary: All Files Involved

| #   | Layer      | File                                  | Role                                                        |
| --- | ---------- | ------------------------------------- | ----------------------------------------------------------- |
| 1   | HTML       | `front-desk-dashboard.component.html` | Renders stat cards + child component                        |
| 2   | HTML       | `registered-patients.component.html`  | Renders the patient table with `p-table`                    |
| 3   | Component  | `front-desk-dashboard.component.ts`   | Calls service, processes data, feeds template               |
| 4   | Component  | `registered-patients.component.ts`    | Receives `@Input() patients` and displays them              |
| 5   | Service    | `user.service.ts`                     | Sends `GET /api/users/patients` via HttpClient              |
| 6   | Controller | `UserController.java`                 | Receives HTTP request, checks roles                         |
| 7   | Service    | `UserServiceImpl.java`                | Runs 3 batch queries + assembles response                   |
| 8   | Service    | `VitalsServiceImpl.java`              | Delegates to repository for batch vitals fetch              |
| 9   | Mapper     | `PatientMapper.java`                  | Auto-converts `User` → `PatientResponse`                    |
| 10  | Repository | `UserRepository.java`                 | `findByRole()` → SQL for users table                        |
| 11  | Repository | `VitalsRepository.java`               | `findLatestVitalsByPatients()` → SQL for vitals             |
| 12  | Repository | `AppointmentRepository.java`          | `findLatestAppointmentsByPatients()` → SQL for appointments |
| 13  | Entity     | `User.java`                           | Maps to `users` DB table                                    |
| 14  | Entity     | `BaseEntity.java`                     | Provides audit fields + soft delete                         |
| 15  | DTO        | `PatientResponse.java`                | Response structure (no password!)                           |
| 16  | DTO        | `VitalsResponse.java`                 | Vitals data structure                                       |
| 17  | DTO        | `LatestAppointmentResponse.java`      | Appointment summary structure                               |

**Total DB queries: 3** | **Total network calls: 1** | **Password exposed: Never** ✅
