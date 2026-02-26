package com.example.DMS_Backend.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class VitalsMissingException extends RuntimeException {
    public VitalsMissingException(String message) {
        super(message);
    }
}
