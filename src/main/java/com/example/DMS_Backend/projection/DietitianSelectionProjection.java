package com.example.DMS_Backend.projection;

/**
 * Interface-based projection for dietitian selection ,
 * Fetches only the necessary fields for listing dietitians.
 */
public interface DietitianSelectionProjection {
    Long getId();

    String getUsername();

    String getFirstName();

    String getLastName();
}   
