package com.example.DMS_Backend.service;

import com.example.DMS_Backend.models.DietitianSchedule;
import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.repositories.DietitianScheduleRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalTime;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class DietitianScheduleService {

    private final DietitianScheduleRepository dietitianScheduleRepository;

    @Transactional
    public void createDefaultSchedule(User dietitian) {
        String[] days = { "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY" };

        List<DietitianSchedule> existingSchedules = dietitianScheduleRepository.findByDietitian(dietitian);
        Set<String> existingDays = existingSchedules.stream()
                .map(DietitianSchedule::getDayOfWeek)
                .collect(Collectors.toSet());

        List<DietitianSchedule> newSchedules = new ArrayList<>();
        for (String day : days) {
            if (!existingDays.contains(day)) {
                newSchedules.add(DietitianSchedule.builder()
                        .dietitian(dietitian)
                        .dayOfWeek(day)
                        .startTime(LocalTime.of(9, 0))
                        .endTime(LocalTime.of(17, 0))
                        .isAvailable(true)
                        .build());
            }
        }

        if (!newSchedules.isEmpty()) {
            dietitianScheduleRepository.saveAll(newSchedules);
        }
    }
}
