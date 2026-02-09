package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.models.Role;
import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.security.jwt.JwtUtils;
import com.example.DMS_Backend.service.AuthService;
import com.example.DMS_Backend.dto.request.LoginRequest;
import com.example.DMS_Backend.dto.request.SignupRequest;
import com.example.DMS_Backend.dto.response.JwtResponse;
import com.example.DMS_Backend.dto.response.MessageResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Optional;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

        @Autowired
        private AuthService authService;

        @Autowired
        private JwtUtils jwtUtils;

        @PostMapping("/login")
        public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
                // Authenticate user
                Optional<User> userOptional = authService.authenticate(
                                loginRequest.getUsername(),
                                loginRequest.getPassword());

                if (userOptional.isEmpty()) {
                        return ResponseEntity
                                        .badRequest()
                                        .body(new MessageResponse("Error: Invalid username or password!"));
                }

                User user = userOptional.get();
                String roleString = user.getRole().name();

                // Generate JWT token with username and role
                String jwt = jwtUtils.generateToken(user.getUsername(), roleString);

                // Return token and user info
                return ResponseEntity.ok(new JwtResponse(
                                jwt,
                                user.getId(),
                                user.getUsername(),
                                user.getEmail(),
                                Collections.singletonList(roleString)));
        }

        @PostMapping("/register")
        public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
                // Check if username already exists
                if (authService.existsByUsername(signUpRequest.getUsername())) {
                        return ResponseEntity
                                        .badRequest()
                                        .body(new MessageResponse("Error: Username is already taken!"));
                }

                // Check if email already exists
                if (authService.existsByEmail(signUpRequest.getEmail())) {
                        return ResponseEntity
                                        .badRequest()
                                        .body(new MessageResponse("Error: Email is already in use!"));
                }

                // Create new user (password will be encoded in AuthService)
                User user = new User(
                                signUpRequest.getUsername(),
                                signUpRequest.getEmail(),
                                signUpRequest.getPassword(), // Plain text, will be encoded
                                Role.valueOf(signUpRequest.getRole()));

                authService.register(user);

                return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
        }
}
