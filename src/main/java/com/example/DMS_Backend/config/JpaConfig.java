package com.example.DMS_Backend.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class JpaConfig {

    @org.springframework.context.annotation.Bean
    public org.springframework.data.domain.AuditorAware<String> auditorProvider() {
        return new AuditorAwareImpl();
    }
}
