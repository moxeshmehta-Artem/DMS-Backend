package com.example.DMS_Backend.repositories;

import com.example.DMS_Backend.models.Vitals;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface VitalsRepository extends JpaRepository<Vitals, Long> {
    List<Vitals> findByPatientIdOrderByRecordedAtDesc(Long patientId);
}
