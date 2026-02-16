# Vitals Module Documentation

## Overview
The Vitals Module is responsible for recording and managing patient vital signs, including height, weight, BMI, blood pressure, heart rate, and temperature.

## Components

### 1. Domain Model (`Vitals`)
- **Table**: `vitals`
- **Fields**:
  - `id`: Primary Key
  - `patient`: Many-to-One relationship with `User`
  - `height`: Patient's height (cm/m)
  - `weight`: Patient's weight (kg)
  - `bmi`: Calculated Body Mass Index
  - `bpSystolic`: Systolic Blood Pressure
  - `bpDiastolic`: Diastolic Blood Pressure
  - `heartRate`: Heart Rate (bpm)
  - `temperature`: Body Temperature
  - `recordedAt`: Timestamp of the record

### 2. Repository (`VitalsRepository`)
- Extends `JpaRepository`.
- **Method**: `findByPatientIdOrderByRecordedAtDesc(Long patientId)` - Retrieves vitals history ordered by most recent.

### 3. DTOs
- **Request**: `VitalsRequest` (Validation enabled)
- **Response**: `VitalsResponse`

### 4. Service (`VitalsService`)
- **Logic**:
  - `addVitals`: Fetches patient, calculates BMI, saves vital record.
  - `getVitalsHistory`: Retrieves and maps vitals to response DTOs.
  - **BMI Calculation**: `weight / (height_in_meters^2)`

### 5. Controller (`VitalsController`)
- **Base URL**: `/api/v1/patients/{patientId}/vitals`
- **Endpoints**:
  - `POST /`: Record new vitals (Roles: DOCTOR, NURSE, ADMIN, FRONTDESK).
  - `GET /`: specific patient's vitals history (Roles: DOCTOR, NURSE, ADMIN, PATIENT, FRONTDESK).

## Usage Example

### Record Vitals
**POST** `/api/v1/patients/{patientId}/vitals`
```json
{
  "height": 175.5,
  "weight": 70.0,
  "bpSystolic": 120,
  "bpDiastolic": 80,
  "heartRate": 72,
  "temperature": 36.6
}
```

### Get History
**GET** `/api/v1/patients/{patientId}/vitals`
```json
[
  {
    "id": 1,
    "height": 175.5,
    "weight": 70.0,
    "bmi": 22.7,
    "bpSystolic": 120,
    "bpDiastolic": 80,
    "heartRate": 72,
    "temperature": 36.6,
    "recordedAt": "2023-10-27T10:00:00"
  }
]
```
