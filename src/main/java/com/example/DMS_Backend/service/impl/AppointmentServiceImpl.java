package com.example.DMS_Backend.service.impl;

import com.example.DMS_Backend.dto.request.AppointmentRequest;
import com.example.DMS_Backend.dto.response.AppointmentResponse;
import com.example.DMS_Backend.entities.Appointment;
import com.example.DMS_Backend.entities.AppointmentStatus;
import com.example.DMS_Backend.entities.User;
import com.example.DMS_Backend.exception.BookingConflictException;
import com.example.DMS_Backend.exception.ResourceNotFoundException;
import com.example.DMS_Backend.exception.VitalsMissingException;
import com.example.DMS_Backend.mapper.AppointmentMapper;
import com.example.DMS_Backend.repositories.AppointmentRepository;
import com.example.DMS_Backend.repositories.DietitianScheduleRepository;
import com.example.DMS_Backend.repositories.UserRepository;
import com.example.DMS_Backend.repositories.VitalsRepository;
import com.example.DMS_Backend.service.AppointmentService;
import lombok.RequiredArgsConstructor;
import com.example.DMS_Backend.entities.DietitianSchedule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AppointmentServiceImpl implements AppointmentService {

        private final AppointmentRepository appointmentRepository;
        private final UserRepository userRepository;
        private final VitalsRepository vitalsRepository;
        private final DietitianScheduleRepository dietitianScheduleRepository;
        private final AppointmentMapper appointmentMapper;

        @Override
        @Transactional
        //book an appointment
        public AppointmentResponse bookAppointment(AppointmentRequest request) {
                User patient = userRepository.findById(request.getPatientId())
                                .orElseThrow(() -> new ResourceNotFoundException(
                                                "Patient not found with ID: " + request.getPatientId()));
                User provider = userRepository.findById(request.getProviderId())
                                .orElseThrow(() -> new ResourceNotFoundException(
                                                "Provider not found with ID: " + request.getProviderId()));

                if (!vitalsRepository.existsByPatient(patient)) {
                        log.info("Booking restriction: Patient {} has no vitals recorded", patient.getId());
                        throw new VitalsMissingException(
                                        "Vitals not recorded yet. Please record vitals before booking an appointment.");
                }

                List<Appointment> patientActiveAppointments = appointmentRepository.findByPatientAndStatusIn(
                                patient, Arrays.asList(AppointmentStatus.PENDING, AppointmentStatus.CONFIRMED));

                if (!patientActiveAppointments.isEmpty()) {
                        log.info("Booking restriction: Patient {} already has an active appointment", patient.getId());
                        throw new BookingConflictException(
                                        "You already have an active appointment. Please complete it before booking another.");
                }
                                //Race condition check
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
                        throw new BookingConflictException(msg);
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
                return appointmentMapper.toResponse(saved);
        }

        //get appointments for a specific patient (On Patient dashboard)
        @Override
        public List<AppointmentResponse> getPatientAppointments(Long patientId) {
                User patient = userRepository.findById(patientId)
                                .orElseThrow(() -> new ResourceNotFoundException(
                                                "Patient not found with ID: " + patientId));
                return appointmentRepository.findByPatient(patient).stream()
                                .map(appointmentMapper::toResponse)
                                .collect(Collectors.toList());
        }

        //get appointments for a specific provider(on dietitian dashboard)
        @Override
        public List<AppointmentResponse> getProviderAppointments(Long providerId) {
                User provider = userRepository.findById(providerId)
                                .orElseThrow(() -> new ResourceNotFoundException(
                                                "Provider not found with ID: " + providerId));
                return appointmentRepository.findByDietitian(provider).stream()
                                .map(appointmentMapper::toResponse)
                                .collect(Collectors.toList());
        }

        //get all appointments(frontdesk-dashboard)
        @Override
        public List<AppointmentResponse> getAllAppointments() {
                return appointmentRepository.findAll().stream()
                                .map(appointmentMapper::toResponse)
                                .collect(Collectors.toList());
        }

        //update the status of the appointment(on dietitian-dashboard)
        @Override
        @Transactional
        public AppointmentResponse updateStatus(Long id, AppointmentStatus status, String notes) {
                Appointment appointment = appointmentRepository.findById(id)
                                .orElseThrow(() -> new ResourceNotFoundException(
                                                "Appointment not found with ID: " + id));

                appointment.setStatus(status);
                if (notes != null) {
                        appointment.setNotes(notes);
                }

                return appointmentMapper.toResponse(appointmentRepository.save(appointment));
        }
        //check for the availability of the slots(on dietitian dashboard)
        @Override
        public List<String> getAvailableSlots(Long providerId, LocalDate date) {
                User provider = userRepository.findById(providerId)
                                .orElseThrow(() -> new ResourceNotFoundException("Provider not found"));

                String dayOfWeek = date.getDayOfWeek().name();
                Optional<DietitianSchedule> scheduleOpt = dietitianScheduleRepository
                                .findByDietitianAndDayOfWeek(provider, dayOfWeek);

                if (scheduleOpt.isEmpty() || !scheduleOpt.get().isAvailable()) {
                        log.info("No available schedule found for provider {} on {}", providerId, dayOfWeek);
                        return new ArrayList<>();
                }

                DietitianSchedule schedule = scheduleOpt.get();
                LocalTime startTime = schedule.getStartTime();
                LocalTime endTime = schedule.getEndTime();

                List<String> allSlots = new ArrayList<>();
                LocalTime current = startTime;
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("hh:mm a", Locale.ENGLISH);

                while (current.isBefore(endTime)) {
                        allSlots.add(current.format(formatter));
                        current = current.plusHours(1);
                }

                List<Appointment> bookedAppointments = appointmentRepository
                                .findByAppointmentDateAndDietitianAndStatusIn(
                                                date,
                                                provider,
                                                Arrays.asList(AppointmentStatus.CONFIRMED, AppointmentStatus.PENDING));

                List<String> bookedSlots = bookedAppointments.stream()
                                .map(Appointment::getTimeSlot)
                                .collect(Collectors.toList());
        
                List<String> availableSlots = allSlots.stream()
                                .filter(slot -> !bookedSlots.contains(slot))
                                .collect(Collectors.toList());

                if (date.equals(LocalDate.now())) {
                        LocalTime now = LocalTime.now();
                        availableSlots = availableSlots.stream()
                                        .filter(slot -> {
                                                LocalTime slotTime = parseTimeSlot(slot);
                                                return slotTime.isAfter(now);
                                        })
                                        .collect(Collectors.toList());
                }

                log.info("Available slots for provider {} on {}: {}", providerId, date, availableSlots);
                return availableSlots;
        }

        private LocalTime parseTimeSlot(String timeSlot) {
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("hh:mm a", Locale.ENGLISH);
                return LocalTime.parse(timeSlot, formatter);
        }
}
