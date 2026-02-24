package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.request.LoginRequest;
import com.example.DMS_Backend.dto.request.SignupRequest;
import com.example.DMS_Backend.dto.response.JwtResponse;
import java.util.Optional;

public interface AuthService {
    Optional<JwtResponse> login(LoginRequest loginRequest);

    void registerUser(SignupRequest signUpRequest);
}
