package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.request.DietPlanRequest;
import com.example.DMS_Backend.dto.response.DietPlanResponse;
import com.example.DMS_Backend.exception.ResourceNotFoundException;
import com.example.DMS_Backend.entities.DietPlan;
import com.example.DMS_Backend.entities.User;
import com.example.DMS_Backend.repositories.DietPlanRepository;
import com.example.DMS_Backend.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class DietPlanService {

    private final DietPlanRepository dietPlanRepository;
    private final UserRepository userRepository;
    private final com.example.DMS_Backend.mapper.DietPlanMapper dietPlanMapper;

    @Transactional
    public DietPlanResponse createDietPlan(Long patientId, DietPlanRequest request) {
        User patient = userRepository.findById(patientId)
                .orElseThrow(() -> new ResourceNotFoundException("Patient not found"));

        User dietitian = userRepository.findById(request.getDietitianId())
                .orElseThrow(() -> new ResourceNotFoundException("Dietitian not found"));

        DietPlan dietPlan = DietPlan.builder()
                .patient(patient)
                .assignedBy(dietitian)
                .breakfast(request.getBreakfast())
                .lunch(request.getLunch())
                .dinner(request.getDinner())
                .snacks(request.getSnacks())
                .build();

        DietPlan saved = dietPlanRepository.save(dietPlan);
        return dietPlanMapper.toResponse(saved);
    }

    public DietPlanResponse getLatestDietPlan(Long patientId) {
        User patient = userRepository.findById(patientId)
                .orElseThrow(() -> new ResourceNotFoundException("Patient not found"));

        return dietPlanRepository.findFirstByPatientOrderByCreatedAtDesc(patient)
                .map(dietPlanMapper::toResponse)
                .orElse(null);
    }

    public List<DietPlanResponse> getDietPlanHistory(Long patientId) {
        User patient = userRepository.findById(patientId)
                .orElseThrow(() -> new ResourceNotFoundException("Patient not found"));

        return dietPlanRepository.findByPatientOrderByCreatedAtDesc(patient).stream()
                .map(dietPlanMapper::toResponse)
                .collect(Collectors.toList());
    }
}
