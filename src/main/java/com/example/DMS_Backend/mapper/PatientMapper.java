package com.example.DMS_Backend.mapper;

import com.example.DMS_Backend.dto.response.PatientResponse;
import com.example.DMS_Backend.models.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface PatientMapper {
    @Mapping(target = "vitals", ignore = true) // Handled separately due to complex logic
    @Mapping(target = "age", source = "age")
    PatientResponse toResponse(User user);
}
