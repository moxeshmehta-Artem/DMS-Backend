# Appointment Booking System: Line-by-Line Logic

This document provides a detailed, line-by-line explanation of how the system calculates available slots and handles the booking process.

---

## 🏗️ 1. Backend: Calculate Available Slots
**File**: `AppointmentServiceImpl.java` -> `getAvailableSlots(...)`

### Line-by-Line Breakdown:

| Line of Code | Explanation | Example / Value |
| :--- | :--- | :--- |
| `User provider = userRepository.findById(providerId)...` | Fetches the Dietitian from the DB using the ID. | `providerId: 5` (Dr. Sarah) |
| `String dayOfWeek = date.getDayOfWeek().name();` | Converts the selected date into its name (UPPERCASE). | `2024-03-04` -> `"MONDAY"` |
| `Optional<DietitianSchedule> scheduleOpt = ...` | Looks for "Dr. Sarah" + "MONDAY" in the schedule table. | Returns 9 AM - 5 PM schedule. |
| `if (scheduleOpt.isEmpty() \|\| !isAvailable())` | If no schedule exists or they are on leave, stop here. | `[]` (Empty List) |
| `LocalTime current = startTime;` | Initializes the starting point for our loop. | `09:00` |
| `while (current.isBefore(endTime))` | Start a loop that runs until we reach the end of the shift. | Breaks at `17:00` |
| `allSlots.add(current.format(formatter));` | Formats time into a string and adds to a temporary list. | `"09:00 AM"` |
| `current = current.plusHours(1);` | Increments the time by 1 hour for the next slot. | `10:00`, `11:00`... |
| `List<Appointment> bookedAppointments = ...` | Queries DB for any *existing* PENDING/CONFIRMED bookings. | Found booking at `10:00 AM`. |
| `List<String> bookedSlots = ...map(Appointment::getTimeSlot)` | Extracts just the time strings from those bookings. | `["10:00 AM"]` |
| `allSlots.stream().filter(slot -> !bookedSlots.contains(slot))` | Removes the booked times from the "all potential slots" list. | 10 AM is now gone. |
| `if (date.equals(LocalDate.now()))` | Checks if the user is trying to book for **Today**. | True if today is March 4th. |
| `filter(slot -> parseTimeSlot(slot).isAfter(now))` | Compares each slot to the current time. | If it's 2 PM now, remove 9 AM - 1 PM. |

**Final Example Output**:
If Dr. Sarah works 9 AM - 5 PM, has a 10 AM booking, and it is currently 12 PM:
`Result: ["01:00 PM", "02:00 PM", "03:00 PM", "04:00 PM"]`

---

## 🌐 2. Frontend: User Selection & State
**File**: `doctor-selection.component.ts` -> `updateAvailableSlots(...)`

### Line-by-Line Breakdown:

| Line of Code | Explanation | Example / Scenario |
| :--- | :--- | :--- |
| `updateAvailableSlots(selectedDate?: Date)` | Method triggered by clicking a date on the calendar. | `selectedDate` = March 4th. |
| `if (selectedDate) { this.bookingDate = selectedDate; }` | Syncs the class property with the event data immediately. | `this.bookingDate` is now updated. |
| `if (!this.bookingDate \|\| !this.selectedDietitian) return;` | Safety check: Don't call the API if we don't know the date/doc. | Stops if calendar was cleared. |
| `const selectedDateStr = this.formatDate(this.bookingDate);` | Formats JS Date object to a string the backend likes. | `"2024-03-04"` |
| `this.appointmentService.getAvailableSlots(...).subscribe(...)` | Makes the HTTP GET request to the backend. | Requesting Dr. Sarah's slots. |
| `this.availableTimeSlots = slots;` | Updates the array used by the `p-dropdown`. | Dropdown now shows 4 times. |
| `if (this.bookingTime && !slots.includes(this.bookingTime))` | If the user previously chose a time that's now gone, reset it. | User picked 10 AM, but it's gone. |
| `this.bookingTime = undefined;` | Clears the selection to prevent invalid booking. | Force user to pick a new time. |

---

## � 3. Summary of End-to-End Flow
1. **User Action**: Clicks "March 4th" in the UI.
2. **Frontend**: Calls `/available-slots?providerId=5&date=2024-03-04`.
3. **Backend**: 
   - Checks Dr. Sarah's Schedule (9-5).
   - Checks DB for bookings (Finds 10 AM).
   - If today is March 4th (12 PM), it hides all slots before 1 PM.
4. **Backend**: Returns `["01:00 PM", "02:00 PM", ...]`
5. **Frontend**: The "Select Time Slot" dropdown automatically populates with these values.
