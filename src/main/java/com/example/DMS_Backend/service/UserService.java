package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.response.PatientResponse;
import java.util.List;

public interface UserService {
    List<PatientResponse> getAllUsers();

    List<PatientResponse> getAllPatients();

    List<PatientResponse> getAllDietitians();

    void deleteUser(Long id);
}
