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
                                .patientName(getFullName(appointment.getPatient()))
                                .providerId(appointment.getDietitian().getId())
                                .providerName(getFullName(appointment.getDietitian()))
                                .appointmentDate(appointment.getAppointmentDate())
                                .timeSlot(appointment.getTimeSlot())
                                .status(appointment.getStatus())
                                .description(appointment.getDescription())
                                .notes(appointment.getNotes())
                                .success(true)
                                .build();
        }

        public List<String> getAvailableSlots(Long providerId, java.time.LocalDate date) {
                User provider = userRepository.findById(providerId)
                                .orElseThrow(() -> new ResourceNotFoundException("Provider not found"));

                // 1. Define Standard Slots (Could be moved to config/DB later)
                List<String> allSlots = Arrays.asList(
                                "09:00 AM", "10:00 AM", "11:00 AM", "12:00 PM",
                                "01:00 PM", "02:00 PM", "03:00 PM", "04:00 PM", "05:00 PM");

                // 2. Fetch Booked Slots (CONFIRMED or PENDING)
                List<Appointment> bookedAppointments = appointmentRepository
                                .findByAppointmentDateAndDietitianAndStatusIn(
                                                date,
                                                provider,
                                                Arrays.asList(AppointmentStatus.CONFIRMED, AppointmentStatus.PENDING));

                List<String> bookedSlots = bookedAppointments.stream()
                                .map(Appointment::getTimeSlot)
                                .collect(Collectors.toList());

                // 3. Subtract Booked from All
                List<String> availableSlots = allSlots.stream()
                                .filter(slot -> !bookedSlots.contains(slot))
                                .collect(Collectors.toList());

                // 4. Filter out past slots if date is today
                if (date.equals(java.time.LocalDate.now())) {
                        java.time.LocalTime now = java.time.LocalTime.now();
                        availableSlots = availableSlots.stream()
                                        .filter(slot -> {
                                                java.time.LocalTime slotTime = parseTimeSlot(slot);
                                                return slotTime.isAfter(now);
                                        })
                                        .collect(Collectors.toList());
                }

                return availableSlots;
        }

        private java.time.LocalTime parseTimeSlot(String timeSlot) {
                // timeSlot format: "09:00 AM"
                java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("hh:mm a",
                                java.util.Locale.ENGLISH);
                return java.time.LocalTime.parse(timeSlot, formatter);
        }

        private String getFullName(User user) {
                String firstName = user.getFirstName();
                String lastName = user.getLastName();

                if (firstName != null && !firstName.isBlank() && lastName != null && !lastName.isBlank()) {
                        return firstName + " " + lastName;
                }

                if (firstName != null && !firstName.isBlank())
                        return firstName;
                if (lastName != null && !lastName.isBlank())
                        return lastName;

                return user.getUsername();
        }
}
