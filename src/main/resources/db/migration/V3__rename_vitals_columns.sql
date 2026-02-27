-- Idempotent Migration to clean up and rename vitals columns

DROP PROCEDURE IF EXISTS cleanup_vitals_columns;

DELIMITER //

CREATE PROCEDURE cleanup_vitals_columns()
BEGIN
    -- 1. If bp_systolic already exists, it might be an empty column added by auto-DDL. 
    -- If it's separate from blood_pressure_sys, let's drop it so we can rename the real one correctly.
    -- We'll only drop it if blood_pressure_sys also exists (to avoid dropping the only data column).
    IF EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'vitals' AND COLUMN_NAME = 'bp_systolic') 
       AND EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'vitals' AND COLUMN_NAME = 'blood_pressure_sys') THEN
        ALTER TABLE vitals DROP COLUMN bp_systolic;
    END IF;

    IF EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'vitals' AND COLUMN_NAME = 'bp_diastolic') 
       AND EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'vitals' AND COLUMN_NAME = 'blood_pressure_dia') THEN
        ALTER TABLE vitals DROP COLUMN bp_diastolic;
    END IF;

    -- 2. Now rename the original columns to the desired names
    IF EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'vitals' AND COLUMN_NAME = 'blood_pressure_sys') THEN
        ALTER TABLE vitals CHANGE COLUMN blood_pressure_sys bp_systolic DOUBLE;
    END IF;

    IF EXISTS (SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'DMS-DB' AND TABLE_NAME = 'vitals' AND COLUMN_NAME = 'blood_pressure_dia') THEN
        ALTER TABLE vitals CHANGE COLUMN blood_pressure_dia bp_diastolic DOUBLE;
    END IF;

END //

DELIMITER ;

CALL cleanup_vitals_columns();

DROP PROCEDURE cleanup_vitals_columns;
