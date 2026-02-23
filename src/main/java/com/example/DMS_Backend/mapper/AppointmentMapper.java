package com.example.DMS_Backend.mapper;

import com.example.DMS_Backend.dto.response.AppointmentResponse;
import com.example.DMS_Backend.entities.Appointment;
import com.example.DMS_Backend.entities.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

@Mapper(componentModel = "spring")
public interface AppointmentMapper {

    @Mapping(target = "patientId", source = "patient.id")
    @Mapping(target = "patientName", source = "patient", qualifiedByName = "fullName")
    @Mapping(target = "providerId", source = "dietitian.id")
    @Mapping(target = "providerName", source = "dietitian", qualifiedByName = "fullName")
    @Mapping(target = "success", constant = "true")
    AppointmentResponse toResponse(Appointment appointment);

    @Named("fullName")
    default String getFullName(User user) {
        if (user == null)
            return null;
        String firstName = user.getFirstName();
        String lastName = user.getLastName();

        if (firstName != null && !firstName.isBlank() && lastName != null && !lastName.isBlank()) {
            return firstName + " " + lastName;
        }

        if (firstName != null && !firstName.isBlank())
            return firstName;
        if (lastName != null && !lastName.isBlank())
            return lastName;

        return user.getUsername();
    }
}
