package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.request.VitalsRequest;
import com.example.DMS_Backend.dto.response.VitalsResponse;
import com.example.DMS_Backend.entities.User;
import java.util.List;

public interface VitalsService {
    VitalsResponse addVitals(Long patientId, VitalsRequest request);

    List<VitalsResponse> getVitalsHistory(Long patientId);

    VitalsResponse getLatestVitals(Long patientId);

    List<VitalsResponse> getLatestVitalsForPatients(List<User> patients);

    VitalsResponse updateVitals(Long vitalsId, VitalsRequest request);
}
