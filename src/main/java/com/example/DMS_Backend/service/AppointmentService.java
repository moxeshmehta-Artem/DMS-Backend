package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.request.AppointmentRequest;
import com.example.DMS_Backend.dto.response.AppointmentResponse;
import com.example.DMS_Backend.entities.AppointmentStatus;
import java.util.List;
import java.time.LocalDate;

public interface AppointmentService {
        AppointmentResponse bookAppointment(AppointmentRequest request);

        List<AppointmentResponse> getPatientAppointments(Long patientId);

        List<AppointmentResponse> getProviderAppointments(Long providerId);

        List<AppointmentResponse> getAllAppointments();

        AppointmentResponse updateStatus(Long id, AppointmentStatus status, String notes);

        List<String> getAvailableSlots(Long providerId, LocalDate date);
}
