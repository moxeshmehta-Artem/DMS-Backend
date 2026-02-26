package com.example.DMS_Backend.entities;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "vitals")
@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Vitals extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "patient_id", nullable = false)
    private User patient;

    private Double height;
    private Double weight;
    private Double bmi;
    private Double bloodPressureSys;
    private Double bloodPressureDia;
    private Integer heartRate;
    private Double temperature;

}
