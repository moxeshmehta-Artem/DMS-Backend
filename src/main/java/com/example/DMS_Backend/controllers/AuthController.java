package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.dto.request.LoginRequest;
import com.example.DMS_Backend.dto.request.SignupRequest;
import com.example.DMS_Backend.dto.response.JwtResponse;
import com.example.DMS_Backend.dto.response.MessageResponse;
import com.example.DMS_Backend.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

        @Autowired
        private AuthService authService;

        @PostMapping("/login")
        public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
                // Authenticate and get token from service
                Optional<JwtResponse> jwtResponse = authService.login(loginRequest);

                if (jwtResponse.isEmpty()) {
                        return ResponseEntity
                                        .badRequest()
                                        .body(new MessageResponse("Error: Invalid username or password!"));
                }

                return ResponseEntity.ok(jwtResponse.get());
        }

        @PostMapping("/register")
        public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
                try {
                        authService.registerUser(signUpRequest);
                        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
                } catch (RuntimeException e) {
                        return ResponseEntity
                                        .badRequest()
                                        .body(new MessageResponse(e.getMessage()));
                }
        }
}
