# Flow Logic: Diet Plan Management

This document provides a full-stack explanation of how diet plans are created, retrieved, and managed in the system.

---

## 🏗️ 1. Backend: Service Implementation
**File**: `DietPlanServiceImpl.java`

This service handles the core business logic for diet plan persistence and history retrieval.

### Line-by-Line Breakdown:

| Method / Line of Code | Explanation | Logic / Purpose |
| :--- | :--- | :--- |
| **`createDietPlan`** | | |
| `@Transactional` | Ensures the creation is atomic. | **Data Integrity**: If saving the plan fails, the transaction rolls back. |
| `userRepository.findById(patientId)` | Fetches the patient user entity. | **Verification**: Ensures the patient exists. |
| `userRepository.findById(request.getDietitianId())` | Fetches the dietitian user entity. | **Verification**: Ensures the dietitian assigned the plan exists. |
| `DietPlan.builder()...build()` | Constructs a new `DietPlan` entity from the DTO. | **Entity Creation**: Mapping request data to DB structure. |
| `dietPlanRepository.save(dietPlan)` | Persists the new plan to the database. | **Persistence**: Stores the breakfast, lunch, dinner, and snacks. |
| **`getLatestDietPlan`** | | |
| `findFirstByPatientOrderByCreatedAtDesc` | Queries the DB for the single most recent plan. | **Retrieval**: Always shows the "active" or newest plan. |
| **`getDietPlanHistory`** | | |
| `findByPatientOrderByCreatedAtDesc` | Retrieves all historical plans for a patient. | **Retrieval**: Allows users to see changes over time. |

---

## 🌐 2. Frontend: API Integration & UI
**Service**: `patient.service.ts` | **Component**: `diet-plan-view.component.ts`

The frontend provides the interface for both dietitians to create plans and patients to view/download them.

### Line-by-Line Breakdown (Service):

| Line of Code | Explanation | Logic / Purpose |
| :--- | :--- | :--- |
| `saveDietPlan(patientId, plan)` | POST request to `/api/patients/{id}/diet-plans`. | **API Call**: Sends new meal data to the server. |
| `getDietPlan(patientId)` | GET request to `/api/patients/{id}/diet-plans/latest`. | **API Call**: Fetches the newest plan for display. |

### Line-by-Line Breakdown (Component - Download):

| Line of Code | Explanation | Logic / Purpose |
| :--- | :--- | :--- |
| `const doc = new jsPDF();` | Initializes the PDF generation library. | **PDF Export**: Prepares a canvas for the report. |
| `meals.forEach(meal => { ... })` | Iterates through breakfast, lunch, dinner, and snacks. | **Formatting**: Adds colored headers and text for each meal. |
| `doc.save('DietPlan_Patient.pdf')` | Prompts the user to save the generated document. | **User Action**: Provides an offline copy for the patient. |

---

## 📝 3. End-to-End Flow Summary
1.  **Creation**: A **Dietitian** fills out a meal form in the UI. The frontend sends the data to the backend POST endpoint.
2.  **Storage**: The **Backend** validates the users and saves the plan with a "Created At" timestamp.
3.  **Viewing**: When a **Patient** logs in, their dashboard calls the "Latest" endpoint.
4.  **Export**: The **Patient** can click "Download Plan" to generate a professional PDF report containing their assigned meals.
