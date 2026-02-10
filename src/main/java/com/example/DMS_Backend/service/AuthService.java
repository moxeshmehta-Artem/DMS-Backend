package com.example.DMS_Backend.service;

import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Collections;

import com.example.DMS_Backend.security.jwt.JwtUtils;
import com.example.DMS_Backend.dto.request.LoginRequest;
import com.example.DMS_Backend.dto.request.SignupRequest;
import com.example.DMS_Backend.dto.response.JwtResponse;
import com.example.DMS_Backend.models.Role;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    /**
     * Login user and generate JWT token
     */
    public Optional<JwtResponse> login(LoginRequest loginRequest) {
        Optional<User> userOptional = userRepository.findByUsername(loginRequest.getUsername());

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            // Check password
            if (passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                // Generate Token
                String roleString = user.getRole().name();
                String jwt = jwtUtils.generateToken(user.getUsername(), roleString);

                return Optional.of(new JwtResponse(
                        jwt,
                        user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        Collections.singletonList(roleString)));
            }
        }
        return Optional.empty();
    }

    /**
     * Register a new user
     * Throws RuntimeException if user already exists
     */
    public void registerUser(SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            throw new RuntimeException("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new RuntimeException("Error: Email is already in use!");
        }

        // Create new user's account
        User user = new User(
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                passwordEncoder.encode(signUpRequest.getPassword()),
                Role.valueOf(signUpRequest.getRole()));

        user.setFirstName(signUpRequest.getFirstName());
        user.setLastName(signUpRequest.getLastName());

        userRepository.save(user);
    }
}
