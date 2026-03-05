package com.example.DMS_Backend.service.impl;

import com.example.DMS_Backend.dto.response.LatestAppointmentResponse;
import com.example.DMS_Backend.dto.response.PatientResponse;
import com.example.DMS_Backend.dto.response.VitalsResponse;
import com.example.DMS_Backend.entities.*;
import com.example.DMS_Backend.mapper.PatientMapper;
import com.example.DMS_Backend.projection.DietitianSelectionProjection;
import com.example.DMS_Backend.repositories.*;
import com.example.DMS_Backend.service.UserService;
import com.example.DMS_Backend.service.VitalsService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final AppointmentRepository appointmentRepository;
    private final VitalsService vitalsService;
    private final PatientMapper patientMapper;

    @Override
    public List<PatientResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(patientMapper::toResponse)
                .collect(Collectors.toList());
    }

    @Override
    public List<PatientResponse> getAllPatients() {
        List<User> patients = userRepository.findByRole(Role.ROLE_PATIENT);

        // 1. Batch fetch latest vitals
        List<VitalsResponse> allLatestVitals = vitalsService.getLatestVitalsForPatients(patients);
        Map<Long, VitalsResponse> vitalsMap = allLatestVitals.stream()
                .collect(Collectors.toMap(VitalsResponse::getPatientId, v -> v));

        // 2. Batch fetch latest appointments
        List<Appointment> allLatestAppts = appointmentRepository.findLatestAppointmentsByPatients(patients);
        Map<Long, LatestAppointmentResponse> apptMap = allLatestAppts.stream()
                .collect(Collectors.toMap(
                        a -> a.getPatient().getId(),
                        a -> LatestAppointmentResponse.builder()
                                .id(a.getId())
                                .date(a.getAppointmentDate())
                                .status(a.getStatus())
                                .build(),
                        (existing, replacement) -> existing));

        return patients.stream().map(user -> {
            PatientResponse res = patientMapper.toResponse(user);
            res.setVitals(vitalsMap.get(user.getId()));
            res.setLatestAppointment(apptMap.get(user.getId()));
            return res;
        }).collect(Collectors.toList());
    }

    @Override
    public List<DietitianSelectionProjection> getDietitianSelection() {
        return userRepository.findProjectedByRole(Role.ROLE_DIETITIAN);
    }

    @Override
    @Transactional
    public void deleteUser(Long id) {
        userRepository.findById(id).ifPresent(user -> {
            user.setDeleted(true);
            user.setDeletedAt(java.time.LocalDateTime.now());
            userRepository.save(user);
        });
    }
}
