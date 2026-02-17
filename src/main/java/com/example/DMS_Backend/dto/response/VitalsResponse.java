package com.example.DMS_Backend.dto.response;

import lombok.Builder;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Builder
public class VitalsResponse {
    private Long id;
    private Long patientId;
    private Double height;
    private Double weight;
    private Double bmi;
    private Double bloodPressureSys;
    private Double bloodPressureDia;
    private Integer heartRate;
    private Double temperature;
    private LocalDateTime recordedAt;
}
