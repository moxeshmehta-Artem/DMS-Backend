package com.example.DMS_Backend.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class VitalsRequest {

    @NotNull(message = "Height is required")
    private Double height;

    @NotNull(message = "Weight is required")
    private Double weight;

    private Integer bpSystolic;
    private Integer bpDiastolic;
    private Integer heartRate;
    private Double temperature;
}
