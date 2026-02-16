package com.example.DMS_Backend.dto.response;

import lombok.Builder;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Builder
public class VitalsResponse {
    private Long id;
    private Double height;
    private Double weight;
    private Double bmi;
    private Integer bpSystolic;
    private Integer bpDiastolic;
    private Integer heartRate;
    private Double temperature;
    private LocalDateTime recordedAt;
}
