package com.example.DMS_Backend.dto.response;

import com.example.DMS_Backend.models.AppointmentStatus;
import lombok.Builder;
import lombok.Data;
import java.time.LocalDate;

@Data
@Builder
public class AppointmentResponse {
    private Long id;
    private Long patientId;
    private String patientName;
    private Long providerId;
    private String providerName;
    private LocalDate appointmentDate;
    private String timeSlot;
    private AppointmentStatus status;
    private String description;
    private String notes;
}
