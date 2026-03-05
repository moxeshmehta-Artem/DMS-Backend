package com.example.DMS_Backend.entities;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.SQLRestriction;

@Entity
@Table(name = "vitals")
@Data
@SQLRestriction("deleted = false")
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
    private Double bpSystolic;
    private Double bpDiastolic;
    private Integer heartRate;
    private Double temperature;

}
