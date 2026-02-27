package com.example.DMS_Backend.dto.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class VitalsRequest {
    @NotNull
    @Min(0)
    @Max(300)
    private Double height;

    @NotNull
    @Min(0)
    @Max(500)
    private Double weight;

    @Min(0)
    @Max(300)
    private Double bpSystolic;

    @Min(0)
    @Max(300)
    private Double bpDiastolic;

    @Min(0)
    @Max(300)
    private Integer heartRate;

    @Min(30)
    @Max(45)
    private Double temperature;
}
