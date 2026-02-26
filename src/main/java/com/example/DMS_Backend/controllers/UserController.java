package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.config.RequireRole;
import com.example.DMS_Backend.dto.response.PatientResponse;
import com.example.DMS_Backend.projection.DietitianSelectionProjection;
import com.example.DMS_Backend.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping
    @RequireRole("ROLE_ADMIN")
    public ResponseEntity<List<PatientResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/patients")
    @RequireRole({ "ROLE_ADMIN", "ROLE_FRONTDESK", "ROLE_DIETITIAN" })
    public ResponseEntity<List<PatientResponse>> getAllPatients() {
        return ResponseEntity.ok(userService.getAllPatients());
    }

    @GetMapping("/dietitians")
    @RequireRole({ "ROLE_ADMIN", "ROLE_FRONTDESK", "ROLE_PATIENT" })
    public ResponseEntity<List<PatientResponse>> getAllDietitians() {
        return ResponseEntity.ok(userService.getAllDietitians());
    }

    @GetMapping("/dietitians/selection")
    @RequireRole({ "ROLE_ADMIN", "ROLE_FRONTDESK", "ROLE_PATIENT" })
    public ResponseEntity<List<DietitianSelectionProjection>> getDietitianSelection() {
        return ResponseEntity.ok(userService.getDietitianSelection());
    }

    @DeleteMapping("/{id}")
    @RequireRole("ROLE_ADMIN")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.ok().build();
    }
}
