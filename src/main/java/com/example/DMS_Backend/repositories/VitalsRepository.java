package com.example.DMS_Backend.repositories;

import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.models.Vitals;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface VitalsRepository extends JpaRepository<Vitals, Long> {
    List<Vitals> findByPatientOrderByRecordedAtDesc(User patient);

    Optional<Vitals> findFirstByPatientOrderByRecordedAtDesc(User patient);
}
