package com.example.DMS_Backend.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@EqualsAndHashCode(callSuper = true)
@Table(name = "dietitian_schedules", uniqueConstraints = {
        @UniqueConstraint(columnNames = { "dietitian_id", "day_of_week" })
})
public class DietitianSchedule extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "dietitian_id", nullable = false)
    private User dietitian;

    @Column(name = "day_of_week", nullable = false)
    private String dayOfWeek;

    @Column(name = "start_time", nullable = false)
    private LocalTime startTime;

    @Column(name = "end_time", nullable = false)
    private LocalTime endTime;

    @Column(name = "is_available")
    private boolean isAvailable;
}
