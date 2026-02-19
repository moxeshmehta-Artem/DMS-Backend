package com.example.DMS_Backend.service;

import com.example.DMS_Backend.models.DietitianSchedule;
import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.repositories.DietitianScheduleRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class DietitianScheduleService {

    private final DietitianScheduleRepository dietitianScheduleRepository;

    @Transactional
    public void createDefaultSchedule(User dietitian) {
        String[] days = { "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY" };

        for (String day : days) {
            Optional<DietitianSchedule> existing = dietitianScheduleRepository.findByDietitianAndDayOfWeek(dietitian,
                    day);
            if (existing.isEmpty()) {
                DietitianSchedule schedule = DietitianSchedule.builder()
                        .dietitian(dietitian)
                        .dayOfWeek(day)
                        .startTime(LocalTime.of(9, 0))
                        .endTime(LocalTime.of(17, 0))
                        .isAvailable(true)
                        .build();
                dietitianScheduleRepository.save(schedule);
            }
        }
    }
}
