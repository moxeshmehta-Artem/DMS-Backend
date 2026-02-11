package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.request.PatientUpdateDTO;
import com.example.DMS_Backend.dto.response.PatientResponse;
import com.example.DMS_Backend.models.Role;
import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PatientService {

    @Autowired
    private UserRepository userRepository;

    public PatientResponse getPatientById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Error: Patient not found."));

        if (!user.getRole().equals(Role.ROLE_PATIENT)) {
            throw new RuntimeException("Error: User is not a patient.");
        }

        return mapToPatientResponse(user);
    }

    public PatientResponse updatePatientProfile(Long id, PatientUpdateDTO dto) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Error: Patient not found."));

        if (!user.getRole().equals(Role.ROLE_PATIENT)) {
            throw new RuntimeException("Error: User is not a patient.");
        }

        if (dto.getFirstName() != null)
            user.setFirstName(dto.getFirstName());
        if (dto.getLastName() != null)
            user.setLastName(dto.getLastName());
        if (dto.getGender() != null)
            user.setGender(dto.getGender());
        if (dto.getEmail() != null)
            user.setEmail(dto.getEmail()); // Should probably check if email exists if changed

        userRepository.save(user);

        return mapToPatientResponse(user);
    }

    private PatientResponse mapToPatientResponse(User user) {
        return PatientResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .gender(user.getGender())
                .build();
    }
}
