package us.cloud.teachme.authutils.filter;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;
import us.cloud.teachme.authutils.exception.JwtAuthenticationEntryPoint;
import us.cloud.teachme.authutils.service.JwtTokenValidator;

import java.io.IOException;
import java.util.Collections;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenValidator jwtTokenValidator;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    public JwtAuthenticationFilter(
            @Autowired JwtTokenValidator jwtTokenValidator,
            @Autowired JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint
    ) {

        this.jwtTokenValidator = jwtTokenValidator;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws IOException {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            jwtAuthenticationEntryPoint.commence(
                    request,
                    response,
                    new AuthenticationCredentialsNotFoundException("Missing or invalid Authorization header")
            );
            return;
        }

        try {
            String token = authHeader.substring(7);
            Claims claims = jwtTokenValidator.validateToken(token);

            if (claims != null && !jwtTokenValidator.isTokenExpired(claims)) {
                Authentication authentication = new PreAuthenticatedAuthenticationToken(
                        claims,
                        null,
                        Collections.emptyList()
                );
                authentication.setAuthenticated(true);

                SecurityContextHolder.getContext().setAuthentication(authentication);
                filterChain.doFilter(request, response);
            } else {
                jwtAuthenticationEntryPoint.commence(
                        request,
                        response,
                        new AuthenticationCredentialsNotFoundException("Token expired")
                );
            }
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            jwtAuthenticationEntryPoint.commence(
                    request,
                    response,
                    new AuthenticationCredentialsNotFoundException("Invalid token: " + e.getMessage())
            );
        }
    }
}
