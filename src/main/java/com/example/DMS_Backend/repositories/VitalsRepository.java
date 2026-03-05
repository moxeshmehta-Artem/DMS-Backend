package com.example.DMS_Backend.repositories;

import com.example.DMS_Backend.entities.User;
import com.example.DMS_Backend.entities.Vitals;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;

public interface VitalsRepository extends JpaRepository<Vitals, Long> {
    List<Vitals> findByPatientOrderByCreatedAtDesc(User patient);

    Optional<Vitals> findFirstByPatientOrderByCreatedAtDesc(User patient);

    boolean existsByPatient(User patient);

    @Query("SELECT v FROM Vitals v WHERE v.deleted = false AND v.id IN (SELECT MAX(v2.id) FROM Vitals v2 WHERE v2.patient IN :patients AND v2.deleted = false GROUP BY v2.patient)")
    List<Vitals> findLatestVitalsByPatients(@Param("patients") List<User> patients);
}