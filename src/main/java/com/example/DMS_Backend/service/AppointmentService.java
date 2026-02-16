package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.request.AppointmentRequest;
import com.example.DMS_Backend.dto.response.AppointmentResponse;
import com.example.DMS_Backend.models.Appointment;
import com.example.DMS_Backend.models.AppointmentStatus;
import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.repositories.AppointmentRepository;
import com.example.DMS_Backend.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AppointmentService {

    private final AppointmentRepository appointmentRepository;
    private final UserRepository userRepository;

    @Transactional
    public AppointmentResponse bookAppointment(AppointmentRequest request) {
        User patient = userRepository.findById(request.getPatientId())
                .orElseThrow(() -> new RuntimeException("Patient not found"));
        User provider = userRepository.findById(request.getProviderId())
                .orElseThrow(() -> new RuntimeException("Provider not found"));

        // Check for existing appointment in the same slot
        List<Appointment> existing = appointmentRepository.findByAppointmentDateAndDietitian(
                request.getAppointmentDate(), provider);

        boolean isSlotTaken = existing.stream()
                .anyMatch(a -> a.getTimeSlot().equals(request.getTimeSlot()) &&
                        a.getStatus() != AppointmentStatus.CANCELLED &&
                        a.getStatus() != AppointmentStatus.REJECTED);

        if (isSlotTaken) {
            throw new RuntimeException("Time slot is already booked");
        }

        Appointment appointment = Appointment.builder()
                .patient(patient)
                .dietitian(provider)
                .appointmentDate(request.getAppointmentDate())
                .timeSlot(request.getTimeSlot())
                .description(request.getDescription())
                .status(AppointmentStatus.PENDING)
                .build();

        Appointment saved = appointmentRepository.save(appointment);
        return mapToResponse(saved);
    }

    public List<AppointmentResponse> getPatientAppointments(Long patientId) {
        User patient = userRepository.findById(patientId)
                .orElseThrow(() -> new RuntimeException("Patient not found"));
        return appointmentRepository.findByPatient(patient).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public List<AppointmentResponse> getProviderAppointments(Long providerId) {
        User provider = userRepository.findById(providerId)
                .orElseThrow(() -> new RuntimeException("Provider not found"));
        return appointmentRepository.findByDietitian(provider).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public List<AppointmentResponse> getAllAppointments() {
        return appointmentRepository.findAll().stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public AppointmentResponse updateStatus(Long id, AppointmentStatus status, String notes) {
        Appointment appointment = appointmentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Appointment not found"));

        appointment.setStatus(status);
        if (notes != null) {
            appointment.setNotes(notes);
        }

        return mapToResponse(appointmentRepository.save(appointment));
    }

    private AppointmentResponse mapToResponse(Appointment appointment) {
        return AppointmentResponse.builder()
                .id(appointment.getId())
                .patientId(appointment.getPatient().getId())
                .patientName(appointment.getPatient().getFirstName() + " " + appointment.getPatient().getLastName())
                .providerId(appointment.getDietitian().getId())
                .providerName(
                        appointment.getDietitian().getFirstName() + " " + appointment.getDietitian().getLastName())
                .appointmentDate(appointment.getAppointmentDate())
                .timeSlot(appointment.getTimeSlot())
                .status(appointment.getStatus())
                .description(appointment.getDescription())
                .notes(appointment.getNotes())
                .build();
    }
}
