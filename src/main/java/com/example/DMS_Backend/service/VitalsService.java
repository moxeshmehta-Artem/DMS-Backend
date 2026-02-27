package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.request.VitalsRequest;
import com.example.DMS_Backend.dto.response.VitalsResponse;
import com.example.DMS_Backend.entities.User;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import java.util.List;

public interface VitalsService {
    VitalsResponse addVitals(Long patientId, VitalsRequest request);

    List<VitalsResponse> getVitalsHistory(Long patientId);

    Slice<VitalsResponse> getVitalsHistorySliced(Long patientId, Pageable pageable);

    VitalsResponse getLatestVitals(Long patientId);

    List<VitalsResponse> getLatestVitalsForPatients(List<User> patients);

    VitalsResponse updateVitals(Long vitalsId, VitalsRequest request);
}
