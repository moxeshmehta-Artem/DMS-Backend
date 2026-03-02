# Flow Logic: Dietitian Schedule Initialization (with SQL)

This document provides a concrete example and the underlying SQL queries for the automatic setup of a Dietitian's schedule.

---

## 🏗️ 1. The Scenario (Concrete Example)
**Patient**: An Admin registers a new Dietitian named **"Dr. Smith"**.
- **User ID**: `10`
- **Username**: `dr_smith`

---

## 🏛️ 2. Line-by-Line Logic & SQL Queries

| Step | Java Code | SQL Query Executed |
| :--- | :--- | :--- |
| **A. Check Existing** | `findByDietitian(dietitian)` | `SELECT * FROM dietitian_schedules WHERE dietitian_id = 10;` |
| **B. Result** | `existingSchedules` is **Empty** | *(Result: 0 rows returned)* |
| **C. Logic** | `for (String day : days)` | No query. The code prepares 5 Java objects (Mon, Tue, Wed, Thu, Fri). |
| **D. Bulk Insert** | `saveAll(newSchedules)` | `INSERT INTO dietitian_schedules (day_of_week, start_time, end_time, is_available, dietitian_id) VALUES ('MONDAY', '09:00:00', '17:00:00', 1, 10);` |
| | | `INSERT INTO dietitian_schedules (day_of_week, start_time, end_time, is_available, dietitian_id) VALUES ('TUESDAY', '09:00:00', '17:00:00', 1, 10);` |
| | | `INSERT INTO dietitian_schedules ...` (Repeated for WED, THU, FRI) |

---

## 📝 3. Detailed Data Object Example
After step **D**, the database table `dietitian_schedules` will look like this:

| id | day_of_week | start_time | end_time | is_available | dietitian_id |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | MONDAY | 09:00 | 17:00 | 1 (True) | 10 |
| 2 | TUESDAY | 09:00 | 17:00 | 1 (True) | 10 |
| 3 | WEDNESDAY | 09:00 | 17:00 | 1 (True) | 10 |
| 4 | THURSDAY | 09:00 | 17:00 | 1 (True) | 10 |
| 5 | FRIDAY | 09:00 | 17:00 | 1 (True) | 10 |

---

## ❓ Why do we run these queries?

1.  **Safety First (`SELECT`)**: We run the `SELECT` query first to ensure we don't create "duplicate Mondays." If Dr. Smith already had a Monday entry, the code would skip that day and move to the next.
2.  **Efficiency (`INSERT`)**: The `saveAll` command in Spring Data JPA is optimized. Instead of 5 separate slow requests, it can often batch them into one high-speed operation.
3.  **Instant Availability**: Because these queries run during registration, Dr. Smith doesn't have to "set up his profile"—he is ready to receive appointments immediately.
