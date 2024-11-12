package us.cloud.teachme.authutils;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

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

        String currentPath = request.getRequestURI();
        boolean needsAuthentication = AuthenticationUtils.needsAuthentication(currentPath, protectedPaths);

        if (!needsAuthentication) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = extractToken(request, response);
        if (token == null) {
            return;
        }

        try {
            Claims claims = validateAndParseToken(token, response);
            if (claims == null) {
                return;
            }

            request.setAttribute("userId", jwtTokenValidator.getUserId(claims));
            request.setAttribute("userRole", jwtTokenValidator.getUserRole(claims));

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            setUnauthorizedResponse(response, "Invalid or expired token");
        }
    }

    private Claims validateAndParseToken(String token, HttpServletResponse response) throws IOException {
        try {
            Claims claims = jwtTokenValidator.validateToken(token);
            if (jwtTokenValidator.isTokenExpired(claims)) {
                setUnauthorizedResponse(response, "Token expired");
                return null;
            }
            return claims;
        } catch (Exception e) {
            setUnauthorizedResponse(response, "Invalid or expired token");
            return null;
        }
    }

    private String extractToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith("Bearer ")) {
            setUnauthorizedResponse(response, "Missing or invalid Authorization header");
            return null;
        }
        return header.substring(7);
    }

    private void setUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(message);
    }
}
