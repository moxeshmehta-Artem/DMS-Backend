# Production-Level Appointment Architecture (For CTO Review)

## 1. The Current "Optimized" Approach
**Status:** Functional, Efficient for <500 daily users.
**Logic:**
- Time slots are **Hardcoded** in Java (`09:00 AM` to `05:00 PM`).
- Duration is fixed (1 Hour).
- Availability is calculated on-the-fly by subtracting booked appointments.

**Why it is NOT fully "Production Scale":**
1.  **Rigidity:** Every doctor works 9-5. You cannot have Dr. Smith working 10-6 and Dr. Jones working 8-4.
2.  **No Exceptions:** Cannot handle holidays, sick leaves, or lunch breaks easily without code changes.
3.  **Concurrency:** Under high load (e.g., ticketmaster style), two users seeing the same "Available" slot might click "Book" at the same millisecond. One will fail, but the user experience is "race-y".

---

## 2. The "Enterprise / Production" Solution

To scale to thousands of users and support real-world clinics, we move from **"Calculation"** to **"Inventory Management"**.

### A. Database Schema Changes
Instead of calculating slots, we **store** doctor patterns and exceptions.

**New Table: `doctor_schedules`**
| dietitian_id | day_of_week | start_time | end_time | is_active |
| :--- | :--- | :--- | :--- | :--- |
| 101 | MONDAY | 08:00 | 12:00 | true |
| 101 | MONDAY | 13:00 | 17:00 | true |
| 101 | TUESDAY | 09:00 | 17:00 | true |

**New Table: `service_types`**
| id | name | duration_minutes | price |
| :--- | :--- | :--- | :--- |
| 1 | Initial Consultation | 60 | $100 |
| 2 | Follow-up | 30 | $50 |

---

### B. Dynamic Slot Generation (The Algorithm)
Instead of `Arrays.asList("09:00", "10:00")`, the backend does this:
1.  **Input:** Doctor ID + Date (e.g., Mon, May 5th).
2.  **Fetch Schedule:** "Doctor works 8-12 and 1-5 on Mondays".
3.  **Fetch Service:** "Follow-up is 30 mins".
4.  **Generate:**
    *   08:00 - 08:30
    *   08:30 - 09:00
    *   ...
    *   13:00 - 13:30 (Skips 12-1 lunch automatically)

---

### C. Concurrency & Locking (The "Ticketmaster" Problem)
**Problem:** 500 people want the 9:00 AM slot.
**Solution:** Redis Distributed Locks or Database Constraints.

1.  **Unique Constraint (Database Level):**
    `ALTER TABLE appointments ADD CONSTRAINT unique_slot UNIQUE (dietitian_id, appointment_date, time_slot);`
    *   **Result:** The database physically refuses to save a second row. 100% guarantee against double-booking.

2.  **Redis Temporary Hold (User Experience):**
    *   User clicks "9:00 AM".
    *   Backend writes key to Redis: `lock:dietitian:101:date:2026-05-05:time:09:00` (Expires in 5 mins).
    *   Slot appears "Pending" to everyone else immediately.
    *   User has 5 minutes to pay/confirm.

---

### D. Scalability (Caching)
**Logic:** "Available Slots" for a doctor don't change often.
**Strategy:** Cache the calculated list in Redis.
*   **Key:** `slots:dietitian:101:date:2026-05-05`
*   **Value:** `["08:00", "08:30", ...]`
*   **Invalidate:** When a booking happens, clear the cache for that day.

## Summary for CTO
| Feature | Matches Current | Matches Production |
| :--- | :--- | :--- |
| **Availability** | Calculated (Java) | Calculated (DB Rules) |
| **Duration** | Fixed (1hr) | Variable (30m, 15m) |
| **Schedule** | Hardcoded (9-5) | Per-Doctor (DB) |
| **Double Booking** | App Logic Check | DB Unique Constraint |
| **Performance** | Good (Index Scan) | Excellent (Redis Cache) |
