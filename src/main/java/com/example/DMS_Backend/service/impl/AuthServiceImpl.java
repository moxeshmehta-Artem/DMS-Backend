package com.example.DMS_Backend.service.impl;

import com.example.DMS_Backend.dto.request.LoginRequest;
import com.example.DMS_Backend.dto.request.SignupRequest;
import com.example.DMS_Backend.dto.response.JwtResponse;
import com.example.DMS_Backend.entities.Role;
import com.example.DMS_Backend.entities.User;
import com.example.DMS_Backend.repositories.UserRepository;
import com.example.DMS_Backend.security.jwt.JwtUtils;
import com.example.DMS_Backend.service.AuthService;
import com.example.DMS_Backend.service.DietitianScheduleService;
import com.example.DMS_Backend.service.EmailService;
import com.example.DMS_Backend.exception.UserAlreadyExistsException;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.Period;
import java.util.Collections;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final DietitianScheduleService dietitianScheduleService;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    @Override
    public Optional<JwtResponse> login(LoginRequest loginRequest) {
        Optional<User> userOptional = userRepository.findByUsername(loginRequest.getUsername());

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                String roleString = user.getRole().name();
                String jwt = jwtUtils.generateToken(user.getUsername(), roleString, user.getId());

                return Optional.of(JwtResponse.builder()
                        .token(jwt)
                        .id(user.getId())
                        .username(user.getUsername())
                        .email(user.getEmail())
                        .roles(Collections.singletonList(roleString))
                        .build());
            }
        }
        return Optional.empty();
    }

    @Override
    public void registerUser(SignupRequest signUpRequest) {
        log.info("Registration attempt for username: {}, role: {}", signUpRequest.getUsername(),
                signUpRequest.getRole());
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            throw new UserAlreadyExistsException("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new UserAlreadyExistsException("Error: Email is already in use!");
        }

        int age = 0;
        if (signUpRequest.getDateOfBirth() != null) {
            age = Period.between(signUpRequest.getDateOfBirth(), LocalDate.now()).getYears();
        }

        User user = User.builder()
                .username(signUpRequest.getUsername())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .role(Role.valueOf(signUpRequest.getRole()))
                .firstName(signUpRequest.getFirstName())
                .lastName(signUpRequest.getLastName())
                .phone(signUpRequest.getPhone())
                .gender(signUpRequest.getGender())
                .dateOfBirth(signUpRequest.getDateOfBirth())
                .age(age)
                .build();

        userRepository.save(user);

        if (user.getRole() == Role.ROLE_DIETITIAN) {
            dietitianScheduleService.createDefaultSchedule(user);
            // Send email with credentials
            emailService.sendCredentialsEmail(user.getEmail(), user.getFirstName(), user.getUsername(),
                    signUpRequest.getPassword());
        }
    }
}
