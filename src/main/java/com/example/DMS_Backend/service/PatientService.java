package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.request.PatientUpdateDTO;
import com.example.DMS_Backend.dto.response.PatientResponse;

public interface PatientService {
    PatientResponse getPatientById(Long id);

    PatientResponse updatePatientProfile(Long id, PatientUpdateDTO dto);
}
