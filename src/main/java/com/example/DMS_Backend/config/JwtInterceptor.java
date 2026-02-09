package com.example.DMS_Backend.config;

import com.example.DMS_Backend.security.jwt.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Arrays;

/**
 * JWT Interceptor to validate tokens and check role-based access
 */
@Component
public class JwtInterceptor implements HandlerInterceptor {

    @Autowired
    private JwtUtils jwtUtils;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        // Skip for non-controller methods
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }

        HandlerMethod handlerMethod = (HandlerMethod) handler;

        // Check if method or class has @RequireRole annotation
        RequireRole methodAnnotation = handlerMethod.getMethodAnnotation(RequireRole.class);
        RequireRole classAnnotation = handlerMethod.getBeanType().getAnnotation(RequireRole.class);

        // If no role requirement, allow access
        if (methodAnnotation == null && classAnnotation == null) {
            return true;
        }

        // Extract JWT token from Authorization header
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\":\"Missing or invalid Authorization header\"}");
            return false;
        }

        String token = authHeader.substring(7); // Remove "Bearer " prefix

        // Validate token
        if (!jwtUtils.validateJwtToken(token)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\":\"Invalid or expired token\"}");
            return false;
        }

        // Extract username and role from token
        String username = jwtUtils.getUserNameFromJwtToken(token);
        String role = jwtUtils.getRoleFromJwtToken(token);

        // Store in request attributes for controller access
        request.setAttribute("username", username);
        request.setAttribute("role", role);

        // Check role-based access
        RequireRole roleAnnotation = methodAnnotation != null ? methodAnnotation : classAnnotation;
        String[] requiredRoles = roleAnnotation.value();

        if (requiredRoles.length > 0) {
            boolean hasAccess = Arrays.asList(requiredRoles).contains(role);

            if (!hasAccess) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter()
                        .write("{\"error\":\"Access denied. Required roles: " + Arrays.toString(requiredRoles) + "\"}");
                return false;
            }
        }

        return true;
    }
}
