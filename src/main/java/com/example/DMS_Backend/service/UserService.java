package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.response.PatientResponse;
import com.example.DMS_Backend.projection.DietitianSelectionProjection;
import java.util.List;

public interface UserService {
    List<PatientResponse> getAllUsers();

    List<PatientResponse> getAllPatients();

    List<DietitianSelectionProjection> getDietitianSelection();

    void deleteUser(Long id);
}
