package com.example.DMS_Backend.service.impl;

import com.example.DMS_Backend.dto.response.PatientResponse;
import com.example.DMS_Backend.entities.Role;
import com.example.DMS_Backend.entities.User;
import com.example.DMS_Backend.mapper.PatientMapper;
import com.example.DMS_Backend.repositories.UserRepository;
import com.example.DMS_Backend.service.PatientService;
import com.example.DMS_Backend.service.VitalsService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PatientServiceImpl implements PatientService {

    private final UserRepository userRepository;
    private final VitalsService vitalsService;
    private final PatientMapper patientMapper;

    @Override
    // TODO: Check if user is patient
    public PatientResponse getPatientById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Error: Patient not found."));

        if (!user.getRole().equals(Role.ROLE_PATIENT)) {
            throw new RuntimeException("Error: User is not a patient.");
        }

        return mapToPatientResponse(user);
    }
    
    private PatientResponse mapToPatientResponse(User user) {
        PatientResponse response = patientMapper.toResponse(user);
        response.setVitals(vitalsService.getLatestVitals(user.getId()));
        return response;
    }
}
