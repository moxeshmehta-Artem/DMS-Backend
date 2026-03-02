# Flow Logic: Dietitian Schedule Initialization

This document explains the automatic setup of a Dietitian's working hours during their registration process.

---

## 🏗️ 1. Backend: Default Schedule Creation
**File**: `DietitianScheduleServiceImpl.java` -> `createDefaultSchedule(User dietitian)`

This method ensures every new Dietitian has a standard "9-to-5" schedule immediately after they join the system.

### Line-by-Line Breakdown:

| Line of Code | Explanation | Logic / Purpose |
| :--- | :--- | :--- |
| `String[] days = { "MONDAY", "TUESDAY", ... }` | Defines the standard work week. | **Scope**: Monday through Friday. |
| `dietitianScheduleRepository.findByDietitian(...)` | Checks if this dietitian already has any setup. | **Safety**: Prevents overwriting existing custom schedules. |
| `existingSchedules.stream().map(...).collect(...)` | Extracts the names of days already configured. | **Comparison**: Prepares a list of days to "skip". |
| `new ArrayList<>()` | Initializes a temporary list for new records. | **Batching**: Collects all days before saving once. |
| `for (String day : days) { if (!exists) { ... } }` | Loops through Mon-Fri. If a day is missing, builds it. | **Verification**: Only creates the days that are truly missing. |
| `LocalTime.of(9, 0)` / `LocalTime.of(17, 0)` | Sets the default hours from **9:00 AM** to **5:00 PM**. | **Standardization**: Default shift. |
| `dietitianScheduleRepository.saveAll(...)` | Saves all 5 days to the database in one single trip. | **Efficiency**: Minimizes database hits. |

---

## 🌐 2. Frontend: Registration Trigger
**File**: `auth.service.ts` -> `registerDietitian(...)`

This is how the process starts from the user interface.

### Line-by-Line Breakdown:

| Line of Code | Explanation | Logic / Purpose |
| :--- | :--- | :--- |
| `registerDietitian(user: Partial<User>, ...)` | Method called when an admin creates a new dietitian. | **Trigger**: The entry point. |
| `role: 'ROLE_DIETITIAN'` | Hardcodes the role so the backend knows what to do. | **Identification**: Signals the backend to run the schedule logic. |
| `this.register(signupRequest)` | Synchronizes the request to the central auth register function. | **Consistency**: Uses the same logic as patient registration. |

---

## 📝 3. End-to-End Flow Summary
1.  **Frontend Action**: An Admin registers a new doctor through the UI.
2.  **API Call**: Angular sends a registration request to `/api/auth/register`.
3.  **Backend Logic 1**: `AuthServiceImpl` saves the user and detects they are a **Dietitian**.
4.  **Backend Logic 2**: `DietitianScheduleServiceImpl` is called and automatically inserts 5 rows into the `dietitian_schedules` table (Mon-Fri, 9am-5pm).
5.  **Result**: The Dietitian is now **bookable** by patients on the very first day, without any manual setup required!
