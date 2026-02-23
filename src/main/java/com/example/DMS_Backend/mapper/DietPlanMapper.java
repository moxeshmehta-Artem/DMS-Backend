package com.example.DMS_Backend.mapper;

import com.example.DMS_Backend.dto.response.DietPlanResponse;
import com.example.DMS_Backend.entities.DietPlan;
import com.example.DMS_Backend.entities.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

@Mapper(componentModel = "spring")
public interface DietPlanMapper {

    @Mapping(target = "patientId", source = "patient.id")
    @Mapping(target = "patientName", source = "patient", qualifiedByName = "fullName")
    @Mapping(target = "dietitianId", source = "assignedBy.id")
    @Mapping(target = "dietitianName", source = "assignedBy", qualifiedByName = "fullName")
    DietPlanResponse toResponse(DietPlan plan);

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
