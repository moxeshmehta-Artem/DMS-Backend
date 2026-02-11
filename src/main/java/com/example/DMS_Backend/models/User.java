package com.example.DMS_Backend.models;

import jakarta.persistence.*;
import lombok.Data; // Assuming Lombok is added
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = "username"),
        @UniqueConstraint(columnNames = "email")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String email;
    private String password;
    private String gender;

    @Enumerated(EnumType.STRING)
    private Role role;

    // Additional fields
    private String firstName;
    private String lastName;
  
}
