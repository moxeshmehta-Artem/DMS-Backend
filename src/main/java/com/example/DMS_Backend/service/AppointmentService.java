package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.request.AppointmentRequest;
import com.example.DMS_Backend.dto.response.AppointmentResponse;
import com.example.DMS_Backend.exception.ResourceNotFoundException;
import com.example.DMS_Backend.models.Appointment;
import com.example.DMS_Backend.models.AppointmentStatus;
import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.repositories.AppointmentRepository;
import com.example.DMS_Backend.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AppointmentService {

        private final AppointmentRepository appointmentRepository;
        private final UserRepository userRepository;
        private final com.example.DMS_Backend.repositories.VitalsRepository vitalsRepository;

        @Transactional
        public AppointmentResponse bookAppointment(AppointmentRequest request) {
                User patient = userRepository.findById(request.getPatientId())
                                .orElseThrow(() -> new ResourceNotFoundException(
                                                "Patient not found with ID: " + request.getPatientId()));
                User provider = userRepository.findById(request.getProviderId())
                                .orElseThrow(() -> new ResourceNotFoundException(
                                                "Provider not found with ID: " + request.getProviderId()));

                // Check if patient has vitals recorded
                if (!vitalsRepository.existsByPatient(patient)) {
                        String msg = "Vitals not recorded, yet.";
                        log.info("Booking restriction: Patient {} has no vitals recorded", patient.getId());
                        return AppointmentResponse.builder()
                                        .success(false)
                                        .message(msg)
                                        .build();
                }

                // Check if patient already has an ongoing appointment
                List<Appointment> patientActiveAppointments = appointmentRepository.findByPatientAndStatusIn(
                                patient, Arrays.asList(AppointmentStatus.PENDING, AppointmentStatus.CONFIRMED));

                if (!patientActiveAppointments.isEmpty()) {
                        String msg = "You already have an active appointment. Please complete or cancel it before booking another.";
                        log.info("Booking restriction: Patient {} already has an active appointment", patient.getId());
                        return AppointmentResponse.builder()
                                        .success(false)
                                        .message(msg)
                                        .build();
                }

                // Check for existing appointment in the same slot
                List<Appointment> existing = appointmentRepository.findByAppointmentDateAndDietitian(
                                request.getAppointmentDate(), provider);

                boolean isSlotTaken = existing.stream()
                                .anyMatch(a -> a.getTimeSlot().equals(request.getTimeSlot()) &&
                                                a.getStatus() != AppointmentStatus.CANCELLED &&
                                                a.getStatus() != AppointmentStatus.REJECTED);

                if (isSlotTaken) {
                        String msg = "Time slot " + request.getTimeSlot()
                                        + " is already booked for this dietitian on " + request.getAppointmentDate();
                        log.info("Booking conflict: {}", msg);
                        return AppointmentResponse.builder()
                                        .success(false)
                                        .message(msg)
                                        .build();
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
                                .orElseThrow(() -> new ResourceNotFoundException(
                                                "Patient not found with ID: " + patientId));
                return appointmentRepository.findByPatient(patient).stream()
                                .map(this::mapToResponse)
                                .collect(Collectors.toList());
        }

        public List<AppointmentResponse> getProviderAppointments(Long providerId) {
                User provider = userRepository.findById(providerId)
                                .orElseThrow(() -> new ResourceNotFoundException(
                                                "Provider not found with ID: " + providerId));
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
                                .orElseThrow(() -> new ResourceNotFoundException(
                                                "Appointment not found with ID: " + id));

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
                                .patientName(appointment.getPatient().getFirstName() + " "
                                                + appointment.getPatient().getLastName())
                                .providerId(appointment.getDietitian().getId())
                                .providerName(
                                                appointment.getDietitian().getFirstName() + " "
                                                                + appointment.getDietitian().getLastName())
                                .appointmentDate(appointment.getAppointmentDate())
                                .timeSlot(appointment.getTimeSlot())
                                .status(appointment.getStatus())
                                .description(appointment.getDescription())
                                .notes(appointment.getNotes())
                                .success(true)
                                .build();
        }
}
