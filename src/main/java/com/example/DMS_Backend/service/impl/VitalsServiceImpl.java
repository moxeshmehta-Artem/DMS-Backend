package com.example.DMS_Backend.service.impl;

import com.example.DMS_Backend.dto.request.VitalsRequest;
import com.example.DMS_Backend.dto.response.VitalsResponse;
import com.example.DMS_Backend.entities.User;
import com.example.DMS_Backend.entities.Vitals;
import com.example.DMS_Backend.exception.ResourceNotFoundException;
import com.example.DMS_Backend.repositories.UserRepository;
import com.example.DMS_Backend.repositories.VitalsRepository;
import com.example.DMS_Backend.service.VitalsService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class VitalsServiceImpl implements VitalsService {

    private final VitalsRepository vitalsRepository;
    private final UserRepository userRepository;

    @Override
    @Transactional
    public VitalsResponse addVitals(Long patientId, VitalsRequest request) {
        User patient = userRepository.findById(patientId)
                .orElseThrow(() -> new ResourceNotFoundException("Patient not found with ID: " + patientId));

        double bmi = 0;
        if (request.getHeight() > 0 && request.getWeight() > 0) {
            double heightInMeters = request.getHeight() / 100;
            bmi = request.getWeight() / (heightInMeters * heightInMeters);
        }

        Vitals vitals = Vitals.builder()
                .patient(patient)
                .height(request.getHeight())
                .weight(request.getWeight())
                .bmi(bmi)
                .bloodPressureSys(request.getBloodPressureSys())
                .bloodPressureDia(request.getBloodPressureDia())
                .heartRate(request.getHeartRate())
                .temperature(request.getTemperature())
                .build();

        Vitals saved = vitalsRepository.save(vitals);
        return mapToResponse(saved);
    }

    @Override
    public List<VitalsResponse> getVitalsHistory(Long patientId) {
        User patient = userRepository.findById(patientId)
                .orElseThrow(() -> new ResourceNotFoundException("Patient not found with ID: " + patientId));

        return vitalsRepository.findByPatientOrderByCreatedAtDesc(patient).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    @Override
    public VitalsResponse getLatestVitals(Long patientId) {
        User patient = userRepository.findById(patientId)
                .orElseThrow(() -> new ResourceNotFoundException("Patient not found with ID: " + patientId));

        return vitalsRepository.findFirstByPatientOrderByCreatedAtDesc(patient)
                .map(this::mapToResponse)
                .orElse(null);
    }

    @Override
    public List<VitalsResponse> getLatestVitalsForPatients(List<User> patients) {
        if (patients.isEmpty()) {
            return Collections.emptyList();
        }
        return vitalsRepository.findLatestVitalsByPatients(patients).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public VitalsResponse updateVitals(Long vitalsId, VitalsRequest request) {
        Vitals vitals = vitalsRepository.findById(vitalsId)
                .orElseThrow(() -> new ResourceNotFoundException("Vitals record not found with ID: " + vitalsId));

        double bmi = 0;
        if (request.getHeight() > 0 && request.getWeight() > 0) {
            double heightInMeters = request.getHeight() / 100;
            bmi = request.getWeight() / (heightInMeters * heightInMeters);
        }

        vitals.setHeight(request.getHeight());
        vitals.setWeight(request.getWeight());
        vitals.setBmi(bmi);
        vitals.setBloodPressureSys(request.getBloodPressureSys());
        vitals.setBloodPressureDia(request.getBloodPressureDia());
        vitals.setHeartRate(request.getHeartRate());
        vitals.setTemperature(request.getTemperature());

        Vitals updated = vitalsRepository.save(vitals);
        return mapToResponse(updated);
    }

    private VitalsResponse mapToResponse(Vitals vitals) {
        return VitalsResponse.builder()
                .id(vitals.getId())
                .patientId(vitals.getPatient().getId())
                .height(vitals.getHeight())
                .weight(vitals.getWeight())
                .bmi(vitals.getBmi())
                .bloodPressureSys(vitals.getBloodPressureSys())
                .bloodPressureDia(vitals.getBloodPressureDia())
                .heartRate(vitals.getHeartRate())
                .temperature(vitals.getTemperature())
                .recordedAt(vitals.getCreatedAt())
                .build();
    }
}
