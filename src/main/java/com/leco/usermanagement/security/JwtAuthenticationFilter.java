package com.leco.usermanagement.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT authentication filter:
 * - If no Authorization header or not Bearer -> continue (public endpoints allowed).
 * - If Authorization Bearer present and token invalid -> return 401 immediately.
 * - If token valid -> populate SecurityContext and continue.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    public JwtAuthenticationFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        log.debug("Request {} {} Origin: {} Authorization present: {}", request.getMethod(), request.getRequestURI(),
                request.getHeader("Origin"), (header != null && header.startsWith("Bearer ")));

        // No Authorization header or not Bearer -> continue as anonymous (public endpoints)
        if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7);
        try {
            boolean valid = jwtUtils.validateToken(token);
            log.debug("JWT validation result for request {}: {}", request.getRequestURI(), valid);

            if (!valid) {
                // Token supplied but invalid/expired -> respond 401 (Unauthorized)
                log.info("Invalid or expired JWT for request {} from {}", request.getRequestURI(), request.getRemoteAddr());
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"error\":\"Invalid or expired token\"}");
                return;
            }

            // Token valid -> extract subject and roles
            String subject = jwtUtils.getSubject(token);
            if (!StringUtils.hasText(subject)) {
                log.warn("JWT validated but no subject found for request {}", request.getRequestURI());
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"error\":\"Invalid token subject\"}");
                return;
            }

            List<String> roles = jwtUtils.getRoles(token);
            if (roles == null) roles = Collections.emptyList();

            var authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            var auth = new UsernamePasswordAuthenticationToken(subject, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);

            log.debug("Authentication set for subject {} with roles {}", subject, roles);

            filterChain.doFilter(request, response);
        } catch (Exception ex) {
            // Avoid propagating exceptions that would cause 500; return 401 for safety
            log.warn("Exception processing JWT for request {}: {}", request.getRequestURI(), ex.getMessage(), ex);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"Invalid token\"}");
        }
    }
}