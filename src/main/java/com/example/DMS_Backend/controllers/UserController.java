package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.dto.response.PatientResponse;
import com.example.DMS_Backend.models.Role;
import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.repositories.UserRepository;
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
                .build()).collect(Collectors.toList());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/patients")
    public ResponseEntity<List<PatientResponse>> getAllPatients() {
        List<User> patients = userRepository.findByRole(Role.ROLE_PATIENT);

        List<PatientResponse> response = patients.stream().map(user -> PatientResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .gender(user.getGender())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .build()).collect(Collectors.toList());

        return ResponseEntity.ok(response);
    }
}
