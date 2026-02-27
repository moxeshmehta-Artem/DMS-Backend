package com.example.DMS_Backend.repositories;

import com.example.DMS_Backend.entities.User;
import com.example.DMS_Backend.entities.Vitals;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;

public interface VitalsRepository extends JpaRepository<Vitals, Long> {
    List<Vitals> findByPatientOrderByCreatedAtDesc(User patient);

    Slice<Vitals> findByPatient(User patient, Pageable pageable);

    Optional<Vitals> findFirstByPatientOrderByCreatedAtDesc(User patient);

    boolean existsByPatient(User patient);

    @Query("SELECT v FROM Vitals v WHERE v.id IN (SELECT MAX(v2.id) FROM Vitals v2 WHERE v2.patient IN :patients GROUP BY v2.patient)")
    List<Vitals> findLatestVitalsByPatients(@Param("patients") List<User> patients);
}
