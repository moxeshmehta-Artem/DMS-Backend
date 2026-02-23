package com.example.DMS_Backend.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "dietitian_schedules", uniqueConstraints = {
        @UniqueConstraint(columnNames = { "dietitian_id", "day_of_week" })
})
public class DietitianSchedule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "dietitian_id", nullable = false)
    private User dietitian;

    @Column(name = "day_of_week", nullable = false)
    private String dayOfWeek; // e.g., "MONDAY", "TUESDAY"

    @Column(name = "start_time", nullable = false)
    private LocalTime startTime;

    @Column(name = "end_time", nullable = false)
    private LocalTime endTime;

    @Column(name = "is_available")
    private boolean isAvailable;
}
