package com.example.DMS_Backend.mapper;

import com.example.DMS_Backend.dto.response.VitalsResponse;
import com.example.DMS_Backend.entities.Vitals;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface VitalsMapper {

    @Mapping(target = "patientId", source = "patient.id")
    VitalsResponse toResponse(Vitals vitals);
}
