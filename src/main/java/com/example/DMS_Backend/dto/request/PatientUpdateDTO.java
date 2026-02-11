package com.example.DMS_Backend.dto.request;

import lombok.Data;

@Data
public class PatientUpdateDTO {
    private String firstName;
    private String lastName;
    private String gender;
    private String email;
}
