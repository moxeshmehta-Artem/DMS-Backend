package com.example.DMS_Backend.repositories;

import com.example.DMS_Backend.entities.Appointment;
import com.example.DMS_Backend.entities.AppointmentStatus;
import com.example.DMS_Backend.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.time.LocalDate;
import java.util.List;

public interface AppointmentRepository extends JpaRepository<Appointment, Long> {

    @Query("SELECT a FROM Appointment a JOIN a.patient p JOIN a.dietitian d")
    List<Appointment> findAll();

    List<Appointment> findByPatient(User patient);

    List<Appointment> findByDietitian(User dietitian);

    List<Appointment> findByAppointmentDateAndDietitian(LocalDate appointmentDate, User dietitian);

    List<Appointment> findByAppointmentDateAndDietitianAndStatusIn(LocalDate appointmentDate, User dietitian,
            List<AppointmentStatus> statuses);

    List<Appointment> findByPatientAndStatusIn(User patient, List<AppointmentStatus> statuses);

    @Query("SELECT a FROM Appointment a WHERE a.id IN (SELECT MAX(a2.id) FROM Appointment a2 WHERE a2.patient IN :patients GROUP BY a2.patient)")
    List<Appointment> findLatestAppointmentsByPatients(
            @Param("patients") List<User> patients);
}
