package com.example.DMS_Backend.config;

import com.example.DMS_Backend.security.jwt.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Arrays;
import java.util.Collections;

/**
 * JWT Interceptor to validate tokens and check role-based access
 */
@Component
@RequiredArgsConstructor
public class JwtInterceptor implements HandlerInterceptor {

    private final JwtUtils jwtUtils;

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

        // Determine if authentication is REQUIRED
        boolean isAuthRequired = (methodAnnotation != null || classAnnotation != null);

        // Extract JWT token from Authorization header
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // Remove "Bearer " prefix

            // Validate token
            if (jwtUtils.validateJwtToken(token)) {
                // Extract username and role from token
                String username = jwtUtils.getUserNameFromJwtToken(token);
                String role = jwtUtils.getRoleFromJwtToken(token);

                // Store in request attributes for controller access
                request.setAttribute("username", username);
                request.setAttribute("role", role);

                // Synchronize with Spring Security context for JPA Auditing
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        username, null, Collections.singletonList(new SimpleGrantedAuthority(role)));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                // Check role-based access IF required
                if (isAuthRequired) {
                    RequireRole roleAnnotation = methodAnnotation != null ? methodAnnotation : classAnnotation;
                    String[] requiredRoles = roleAnnotation.value();

                    if (requiredRoles.length > 0) {
                        boolean hasAccess = Arrays.asList(requiredRoles).contains(role);
                        if (!hasAccess) {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            response.getWriter().write("{\"error\":\"Access denied. Required roles: "
                                    + Arrays.toString(requiredRoles) + "\"}");
                            return false;
                        }
                    }
                }
            } else if (isAuthRequired) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\":\"Invalid or expired token\"}");
                return false;
            }
        } else if (isAuthRequired) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\":\"Missing or invalid Authorization header\"}");
            return false;
        }

        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)
            throws Exception {
        // Clear security context after request is complete
        SecurityContextHolder.clearContext();
    }
}
