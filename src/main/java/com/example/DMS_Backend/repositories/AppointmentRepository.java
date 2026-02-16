package com.example.DMS_Backend.repositories;

import com.example.DMS_Backend.models.Appointment;
import com.example.DMS_Backend.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDate;
import java.util.List;

public interface AppointmentRepository extends JpaRepository<Appointment, Long> {
    List<Appointment> findByPatient(User patient);

    List<Appointment> findByDietitian(User dietitian);

    List<Appointment> findByAppointmentDateAndDietitian(LocalDate appointmentDate, User dietitian);
}
