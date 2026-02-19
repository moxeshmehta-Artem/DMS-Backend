package com.example.DMS_Backend.repositories;

import com.example.DMS_Backend.models.DietitianSchedule;
import com.example.DMS_Backend.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.List;

public interface DietitianScheduleRepository extends JpaRepository<DietitianSchedule, Long> {
    Optional<DietitianSchedule> findByDietitianAndDayOfWeek(User dietitian, String dayOfWeek);

    List<DietitianSchedule> findByDietitian(User dietitian);
}
