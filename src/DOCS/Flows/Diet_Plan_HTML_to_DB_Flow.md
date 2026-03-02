# Flow Logic: Diet Plan - From UI (HTML) to Database

This document provides a complete trace of how a Diet Plan is created, from the moment a Dietitian types it into the UI until it's saved in the SQL database.

---

## 🎨 1. Frontend: The UI (HTML)
**File**: `appointment.component.html`

The dietitian clicks "Create Plan" on a confirmed appointment, which opens a PrimeNG Dialog (`p-dialog`).

### Key UI Elements:
- **Input Fields**: Four `textarea` elements bound to the `newPlan` object using `[(ngModel)]`.
  - `newPlan.breakfast`, `newPlan.lunch`, `newPlan.dinner`, `newPlan.snacks`.
- **Validation**: "Save & Complete" button is disabled unless the required fields (Breakfast, Lunch, Dinner) are filled (`[disabled]="!isPlanValid"`).
- **Trigger**: Clicking "Save & Complete" calls `saveDietPlan()`.

---

## ⚙️ 2. Frontend: Component Logic
**File**: `appointment.component.ts` -> `saveDietPlan()`

### Logic Breakdown:
1. **Validation**: Double-checks if `selectedAppt` and `isPlanValid` are true.
2. **Service Call**: Calls `this.patientService.saveDietPlan(patientId, newPlan)`.
3. **Status Sync**: On success, it calls `updateStatus(appt, 'COMPLETED')` to automatically mark the appointment as finished.
4. **Toast**: Shows a "Plan Saved" success message via `MessageService`.

---

## 🌐 3. Frontend: The Service (API Call)
**File**: `patient.service.ts` -> `saveDietPlan(...)`

This is the bridge that communicates with the server.

```typescript
saveDietPlan(patientId: number, plan: DietPlan): Observable<any> {
    const currentUser = this.authService.currentUser();
    const request = {
        ...plan,
        dietitianId: currentUser?.id // Adds the ID of the doctor currently logged in
    };
    return this.http.post(`${this.API_URL}/${patientId}/diet-plans`, request);
}
```
- **Action**: Sends a **POST** request to `http://localhost:8080/api/patients/{id}/diet-plans` with the meal JSON.

---

## 🏛️ 4. Backend: Controller (The Gatekeeper)
**File**: `DietPlanController.java` -> `createDietPlan(...)`

### Process:
1. **URL Mapping**: Listens for the POST request on `/{patientId}/diet-plans`.
2. **Security**: `@RequireRole("ROLE_DIETITIAN")` ensures only doctors can assign plans.
3. **Data Binding**: `@Valid @RequestBody` automatically validates the JSON and converts it into a `DietPlanRequest` object.

---

## 🧠 5. Backend: Service Logic
**File**: `DietPlanServiceImpl.java` -> `createDietPlan(...)`

### Detailed Steps:
1. **Fetch Patient**: `userRepository.findById(patientId)` (Ensures the patient is real).
2. **Fetch Dietitian**: `userRepository.findById(request.getDietitianId())` (Ensures the doctor is real).
3. **Build Entity**: Uses the Builder pattern to create a `DietPlan` object.
4. **Save**: `dietPlanRepository.save(dietPlan)` performs the final SQL `INSERT`.
5. **Return**: Mapped DTO is sent back to the frontend.

---

## 💾 6. The Database
**Table**: `diet_plans`

The final record is inserted with the following columns:
- `id`: Auto-generated PK.
- `patient_id`: FK to User table.
- `assigned_by_id`: FK to dietitian.
- `breakfast`, `lunch`, `dinner`, `snacks`: Text content.
- `created_at`: Automatically timestamped.

---

### 📝 Summary Flow Chart
1. **UI**: User enters "Oats for breakfast" in the HTML.
2. **Angular**: Component gathers data into a JSON package.
3. **Service**: Appends the Doctor's ID and ships it to the API.
4. **Spring Boot**: Validates that both Patient and Doctor are valid users.
5. **Database**: Saves the row. The patient can now see their new plan!
