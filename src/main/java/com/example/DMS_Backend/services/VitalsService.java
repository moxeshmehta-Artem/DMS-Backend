package com.example.DMS_Backend.services;

import com.example.DMS_Backend.dto.request.VitalsRequest;
import com.example.DMS_Backend.dto.response.VitalsResponse;
import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.models.Vitals;
import com.example.DMS_Backend.repositories.UserRepository;
import com.example.DMS_Backend.repositories.VitalsRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class VitalsService {

    private final VitalsRepository vitalsRepository;
    private final UserRepository userRepository;

    @Transactional
    public void addVitals(Long patientId, VitalsRequest request) {
        User patient = userRepository.findById(patientId)
                .orElseThrow(() -> new EntityNotFoundException("Patient not found with id: " + patientId));

        double bmi = calculateBMI(request.getHeight(), request.getWeight());

        Vitals vitals = Vitals.builder()
                .patient(patient)
                .height(request.getHeight())
                .weight(request.getWeight())
                .bmi(bmi)
                .bpSystolic(request.getBpSystolic())
                .bpDiastolic(request.getBpDiastolic())
                .heartRate(request.getHeartRate())
                .temperature(request.getTemperature())
                .build();

        vitalsRepository.save(vitals);
    }

    public List<VitalsResponse> getVitalsHistory(Long patientId) {
        if (!userRepository.existsById(patientId)) {
            throw new EntityNotFoundException("Patient not found with id: " + patientId);
        }

        List<Vitals> vitalsList = vitalsRepository.findByPatientIdOrderByRecordedAtDesc(patientId);

        return vitalsList.stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    private double calculateBMI(double heightCm, double weightKg) {
        if (heightCm <= 0 || weightKg <= 0) {
            return 0.0;
        }
        double heightM = heightCm / 100.0;
        return Math.round((weightKg / (heightM * heightM)) * 100.0) / 100.0;
    }

    private VitalsResponse mapToResponse(Vitals vitals) {
        return VitalsResponse.builder()
                .id(vitals.getId())
                .height(vitals.getHeight())
                .weight(vitals.getWeight())
                .bmi(vitals.getBmi())
                .bpSystolic(vitals.getBpSystolic())
                .bpDiastolic(vitals.getBpDiastolic())
                .heartRate(vitals.getHeartRate())
                .temperature(vitals.getTemperature())
                .recordedAt(vitals.getRecordedAt())
                .build();
    }
}
