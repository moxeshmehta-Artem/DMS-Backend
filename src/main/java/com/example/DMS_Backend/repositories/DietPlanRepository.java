package com.example.DMS_Backend.repositories;

import com.example.DMS_Backend.entities.DietPlan;
import com.example.DMS_Backend.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface DietPlanRepository extends JpaRepository<DietPlan, Long> {
    List<DietPlan> findByPatientOrderByCreatedAtDesc(User patient);

    Optional<DietPlan> findFirstByPatientOrderByCreatedAtDesc(User patient);

    List<DietPlan> findByAssignedBy(User dietitian);
}
