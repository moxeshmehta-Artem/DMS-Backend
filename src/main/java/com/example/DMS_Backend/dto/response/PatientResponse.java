package com.example.DMS_Backend.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PatientResponse {
    private Long id;
    private String username;
    private String gender;
    private String email;
    private String firstName;
    private String lastName;
}
