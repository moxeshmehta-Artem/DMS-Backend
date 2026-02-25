-- Initial schema for  (DMS-Backend)

CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    gender VARCHAR(50),
    age INT,
    date_of_birth DATE,
    role VARCHAR(50) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    phone VARCHAR(50)
);

CREATE TABLE appointments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    patient_id BIGINT NOT NULL,
    dietitian_id BIGINT NOT NULL,
    appointment_date DATE NOT NULL,
    time_slot VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    description TEXT,
    notes TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    CONSTRAINT fk_appointment_patient FOREIGN KEY (patient_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_appointment_dietitian FOREIGN KEY (dietitian_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE diet_plans (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    patient_id BIGINT NOT NULL,
    dietitian_id BIGINT NOT NULL,
    breakfast TEXT,
    lunch TEXT,
    dinner TEXT,
    snacks TEXT,
    created_at TIMESTAMP,
    CONSTRAINT fk_diet_plan_patient FOREIGN KEY (patient_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_diet_plan_dietitian FOREIGN KEY (dietitian_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE dietitian_schedules (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    dietitian_id BIGINT NOT NULL,
    day_of_week VARCHAR(20) NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    is_available BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_schedule_dietitian FOREIGN KEY (dietitian_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (dietitian_id, day_of_week)
);

CREATE TABLE vitals (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    patient_id BIGINT NOT NULL,
    height DOUBLE,
    weight DOUBLE,
    bmi DOUBLE,
    blood_pressure_sys DOUBLE,
    blood_pressure_dia DOUBLE,
    heart_rate INT,
    temperature DOUBLE,
    recorded_at TIMESTAMP,
    CONSTRAINT fk_vitals_patient FOREIGN KEY (patient_id) REFERENCES users(id) ON DELETE CASCADE
);
