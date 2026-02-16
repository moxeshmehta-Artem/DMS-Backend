package com.example.DMS_Backend.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import java.time.LocalDate;

@Data
public class AppointmentRequest {
    @NotNull(message = "Patient ID is required")
    private Long patientId;

    @NotNull(message = "Provider ID is required")
    private Long providerId;

    @NotNull(message = "Appointment date is required")
    private LocalDate appointmentDate;

    @NotBlank(message = "Time slot is required")
    private String timeSlot;

    private String description;
}
