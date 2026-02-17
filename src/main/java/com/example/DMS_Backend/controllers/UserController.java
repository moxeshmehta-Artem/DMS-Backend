package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.dto.response.PatientResponse;
import com.example.DMS_Backend.models.Role;
import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.repositories.AppointmentRepository;
import com.example.DMS_Backend.repositories.UserRepository;
import com.example.DMS_Backend.service.VitalsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AppointmentRepository appointmentRepository;

    @Autowired
    private VitalsService vitalsService;

    @GetMapping
    public ResponseEntity<List<PatientResponse>> getAllUsers() {
        // For now, return ALL users or specific role if needed.
        // Let's filter for valid users (maybe exclude admins in future if needed)
        List<User> users = userRepository.findAll();

        List<PatientResponse> response = users.stream().map(user -> PatientResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .gender(user.getGender())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .age(user.getAge())
                .build()).collect(Collectors.toList());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/patients")
    public ResponseEntity<List<PatientResponse>> getAllPatients() {
        List<User> patients = userRepository.findByRole(Role.ROLE_PATIENT);

        List<PatientResponse> response = patients.stream().map(user -> PatientResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .age(user.getAge())
                .email(user.getEmail())
                .gender(user.getGender())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .vitals(vitalsService.getLatestVitals(user.getId()))
                .build()).collect(Collectors.toList());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/dietitians")
    public ResponseEntity<List<PatientResponse>> getAllDietitians() {
        List<User> dietitians = userRepository.findByRole(Role.ROLE_DIETITIAN);

        List<PatientResponse> response = dietitians.stream().map(user -> PatientResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .gender(user.getGender())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .build()).collect(Collectors.toList());

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{id}")
    @org.springframework.transaction.annotation.Transactional
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        User user = userRepository.findById(id).orElse(null);
        if (user != null) {
            // Manual cascade delete for appointments
            List<com.example.DMS_Backend.models.Appointment> pAppts = appointmentRepository.findByPatient(user);
            List<com.example.DMS_Backend.models.Appointment> dAppts = appointmentRepository.findByDietitian(user);
            appointmentRepository.deleteAll(pAppts);
            appointmentRepository.deleteAll(dAppts);

            userRepository.delete(user);
        }
        return ResponseEntity.ok().build();
    }
}
