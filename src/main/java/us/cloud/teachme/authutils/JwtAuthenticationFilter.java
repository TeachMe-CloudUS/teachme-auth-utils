package us.cloud.teachme.authutils;

import io.jsonwebtoken.Claims;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenValidator jwtTokenValidator;
    private final String[] protectedPaths;

    public JwtAuthenticationFilter(JwtTokenValidator jwtTokenValidator, String[] protectedPaths) {
        this.jwtTokenValidator = jwtTokenValidator;
        this.protectedPaths = protectedPaths;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String requestUri = request.getRequestURI();
        boolean needsAuthentication = false;
        for (String path : protectedPaths) {
            if (requestUri.startsWith(path)) {
                needsAuthentication = true;
                break;
            }
        }

        if (!needsAuthentication) {
            filterChain.doFilter(request, response);
            return;
        }

        // Validate JWT if the request is to a protected path
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Missing or invalid Authorization header");
            return;
        }

        String token = header.substring(7);
        try {
            Claims claims = jwtTokenValidator.validateToken(token);
            if (jwtTokenValidator.isTokenExpired(claims)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Token expired");
                return;
            }

            request.setAttribute("userId", jwtTokenValidator.getUserId(claims));
            request.setAttribute("userRole", jwtTokenValidator.getUserRole(claims));

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid or expired token");
        }
    }
}
