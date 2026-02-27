-- Idempotent Migration to add auditing columns

DROP PROCEDURE IF EXISTS add_audit_columns;

DELIMITER //

CREATE PROCEDURE add_audit_columns()
BEGIN
    -- 1. Users table
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'users' AND COLUMN_NAME = 'created_at') THEN
        ALTER TABLE users ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'users' AND COLUMN_NAME = 'updated_at') THEN
        ALTER TABLE users ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'users' AND COLUMN_NAME = 'created_by') THEN
        ALTER TABLE users ADD COLUMN created_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM';
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'users' AND COLUMN_NAME = 'last_modified_by') THEN
        ALTER TABLE users ADD COLUMN last_modified_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM';
    END IF;

    -- 2. Appointments table
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'appointments' AND COLUMN_NAME = 'created_by') THEN
        ALTER TABLE appointments ADD COLUMN created_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM';
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'appointments' AND COLUMN_NAME = 'last_modified_by') THEN
        ALTER TABLE appointments ADD COLUMN last_modified_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM';
    END IF;

    -- 3. Vitals table
    -- Check if recorded_at exists and needs renaming to created_at
    IF EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'vitals' AND COLUMN_NAME = 'recorded_at') THEN
        ALTER TABLE vitals CHANGE COLUMN recorded_at created_at DATETIME NOT NULL;
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'vitals' AND COLUMN_NAME = 'updated_at') THEN
        ALTER TABLE vitals ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'vitals' AND COLUMN_NAME = 'created_by') THEN
        ALTER TABLE vitals ADD COLUMN created_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM';
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'vitals' AND COLUMN_NAME = 'last_modified_by') THEN
        ALTER TABLE vitals ADD COLUMN last_modified_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM';
    END IF;

    -- 4. Diet Plans table
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'diet_plans' AND COLUMN_NAME = 'updated_at') THEN
        ALTER TABLE diet_plans ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'diet_plans' AND COLUMN_NAME = 'created_by') THEN
        ALTER TABLE diet_plans ADD COLUMN created_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM';
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'diet_plans' AND COLUMN_NAME = 'last_modified_by') THEN
        ALTER TABLE diet_plans ADD COLUMN last_modified_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM';
    END IF;

    -- 5. Dietitian Schedules table
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'dietitian_schedules' AND COLUMN_NAME = 'created_at') THEN
        ALTER TABLE dietitian_schedules ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'dietitian_schedules' AND COLUMN_NAME = 'updated_at') THEN
        ALTER TABLE dietitian_schedules ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'dietitian_schedules' AND COLUMN_NAME = 'created_by') THEN
        ALTER TABLE dietitian_schedules ADD COLUMN created_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM';
    END IF;
    IF NOT EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'dietitian_schedules' AND COLUMN_NAME = 'last_modified_by') THEN
        ALTER TABLE dietitian_schedules ADD COLUMN last_modified_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM';
    END IF;

END //

DELIMITER ;

CALL add_audit_columns();

DROP PROCEDURE add_audit_columns;
