package com.example.DMS_Backend.service.impl;

import com.example.DMS_Backend.dto.request.DietPlanRequest;
import com.example.DMS_Backend.dto.response.DietPlanResponse;
import com.example.DMS_Backend.entities.DietPlan;
import com.example.DMS_Backend.entities.User;
import com.example.DMS_Backend.exception.ResourceNotFoundException;
import com.example.DMS_Backend.mapper.DietPlanMapper;
import com.example.DMS_Backend.repositories.DietPlanRepository;
import com.example.DMS_Backend.repositories.UserRepository;
import com.example.DMS_Backend.service.DietPlanService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class DietPlanServiceImpl implements DietPlanService {

        private final DietPlanRepository dietPlanRepository;
        private final UserRepository userRepository;
        private final DietPlanMapper dietPlanMapper;

        @Override
        @Transactional
        //For Creating a new Diet Plan(Dietitian)
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

        @Override
        //For Getting the Latest Diet Plan(Patient)
        public DietPlanResponse getLatestDietPlan(Long patientId) {
                User patient = userRepository.findById(patientId)
                                .orElseThrow(() -> new ResourceNotFoundException("Patient not found"));

                return dietPlanRepository.findFirstByPatientOrderByCreatedAtDesc(patient)
                                .map(dietPlanMapper::toResponse)
                                .orElse(null);
        }
}
