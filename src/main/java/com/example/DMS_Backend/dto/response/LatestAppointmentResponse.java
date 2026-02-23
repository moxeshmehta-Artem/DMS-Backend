package com.example.DMS_Backend.dto.response;

import com.example.DMS_Backend.entities.AppointmentStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LatestAppointmentResponse {
    private Long id;
    private LocalDate date;
    private AppointmentStatus status;
}
