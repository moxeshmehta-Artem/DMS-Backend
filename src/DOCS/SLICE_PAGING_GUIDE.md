# 🍰 Slice Paging Implementation Guide

We have implemented **Slice Paging** for the Vitals history feature. This document explains the implementation and how to use it.

---

## 1. Why Slice?
We chose `Slice` instead of `Page` because Vitals history is a list that grows indefinitely. 
- **Performance**: It avoids the `SELECT COUNT(*)` query, which is expensive on large tables.
- **UX**: Perfect for "Load More" or Infinite Scroll in the UI.

---

## 2. The Implementation

### Level 1: Repository (`VitalsRepository.java`)
We added a method that takes a `Pageable` and returns a `Slice`.
```java
Slice<Vitals> findByPatient(User patient, Pageable pageable);
```

### Level 2: Service (`VitalsServiceImpl.java`)
We map the database entity slice to a DTO slice.
```java
public Slice<VitalsResponse> getVitalsHistorySliced(Long patientId, Pageable pageable) {
    User patient = userRepository.findById(patientId).orElseThrow(...);
    return vitalsRepository.findByPatient(patient, pageable)
            .map(this::mapToResponse);
}
```

### Level 3: Controller (`VitalsController.java`)
A new endpoint that accepts paging parameters.
```java
@GetMapping("/{patientId}/vitals/paged")
public ResponseEntity<Slice<VitalsResponse>> getPagedVitalsHistory(
        @PathVariable Long patientId,
        Pageable pageable) {
    return ResponseEntity.ok(vitalsService.getVitalsHistorySliced(patientId, pageable));
}
```

---

## 3. How to use it (API Examples)

### Get the first 5 records:
`GET /api/patients/1/vitals/paged?size=5&page=0&sort=createdAt,desc`

### JSON Response Structure:
```json
{
  "content": [...],      // Your 5 vitals records
  "number": 0,           // Current page (0-indexed)
  "size": 5,             // Page size requested
  "numberOfElements": 5, // Items on this page
  "first": true,         // Is this the first slice?
  "last": false,         // Is this the last slice?
  "hasNext": true        // <-- IMPORTANT: Use this for "Load More" button
}
```

---

## 🚀 Pro-Tip
Use `sort=createdAt,desc` in your URL to ensure the user always sees the most recent data first.
