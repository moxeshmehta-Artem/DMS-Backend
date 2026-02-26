# 🛡️ Backend Auditing Guide: How it works

This document explains the **JPA Auditing** system in the DMS Backend. This system automatically tracks **when** data was changed and **who** performed the change.

---

## 🏗️ The 3 Pillars of Auditing

### 1. The Template: `BaseEntity.java`
Instead of adding timestamp fields to 10 different files, we use a "Master Template."
- **File**: [BaseEntity.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/entities/BaseEntity.java)
- **Fields**: 
  - `createdAt`: Set once when the record is created.
  - `updatedAt`: Updated every time the record is saved.
  - `createdBy`: Stores the username of the creator.
  - `lastModifiedBy`: Stores the username of the last editor.
- **How to use**: Simply make your entity extend it: `public class User extends BaseEntity { ... }`.

### 2. The User Tracker: `AuditorAwareImpl.java`
This is the "brain" that knows who is currently using the app.
- **File**: [AuditorAwareImpl.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/AuditorAwareImpl.java)
- **Logic**: It looks into **Spring Security**. 
  - If a Dietitian named `sarah_123` is logged in, it returns `"sarah_123"`.
  - If no one is logged in (e.g., during startup), it returns `"SYSTEM"`.

### 3. The Activation: `JpaConfig.java`
This file turns on the whole system.
- **File**: [JpaConfig.java](file:///home/artem/Desktop/DMS-Main/DMS-Backend/src/main/java/com/example/DMS_Backend/config/JpaConfig.java)
- **Role**: It connects the "User Tracker" to the database logic so that every `save()` operation triggers a check.

---

## ✅ Benefits in Production

1. **Security Audit Trail**: You can always track down which user modified a sensitive record (like a Diet Plan or Vitals).
2. **Boilerplate Reduction**: You no longer need to write `vitals.setRecordedAt(LocalDateTime.now())` in your services. The database handles it silently.
3. **Data Integrity**: Ensures that `updatedAt` is always accurate, which is critical for syncing data with the Frontend.

---

## 🛠️ Refactored Entities
The following entities have been upgraded to use this system:
- `User`
- `Appointment`
- `Vitals`
- `DietPlan`
- `DietitianSchedule`
