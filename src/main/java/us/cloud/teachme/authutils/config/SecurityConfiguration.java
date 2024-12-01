package us.cloud.teachme.authutils.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import us.cloud.teachme.authutils.exception.JwtAuthenticationEntryPoint;
import us.cloud.teachme.authutils.filter.JwtAuthenticationFilter;
import us.cloud.teachme.authutils.service.JwtTokenValidator;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final JwtAuthenticationEntryPoint jwtAuthEntryPoint;
    private final JwtProperties jwtProperties;
    private final JwtTokenValidator jwtTokenValidator;

    public SecurityConfiguration(
            JwtAuthenticationEntryPoint jwtAuthEntryPoint,
            JwtProperties jwtProperties,
            JwtTokenValidator jwtTokenValidator
    ) {
        this.jwtAuthEntryPoint = jwtAuthEntryPoint;
        this.jwtProperties = jwtProperties;
        this.jwtTokenValidator = jwtTokenValidator;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain whiteListFilterChain(HttpSecurity http) throws Exception {
        if (jwtProperties.whiteListedPaths().length == 0) {
            return defaultFilterChain(http);
        }
        return http
                .securityMatcher(jwtProperties.whiteListedPaths())
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        if (jwtProperties.protectedPaths().length == 0) {
            return defaultFilterChain(http);
        }

        return http
                .securityMatcher(request -> {
                    String path = request.getRequestURI();
                    for (String protectedPath : jwtProperties.protectedPaths()) {
                        if (path.matches(protectedPath.replace("**", ".*"))) {
                            return true;
                        }
                    }
                    return false;
                })
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(ex ->
                        ex.authenticationEntryPoint(jwtAuthEntryPoint))
                .addFilterBefore(
                        new JwtAuthenticationFilter(jwtTokenValidator, jwtAuthEntryPoint),
                        UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher(request -> {
                    String path = request.getRequestURI();
                    for (String whitePath : jwtProperties.whiteListedPaths()) {
                        if (path.matches(whitePath.replace("**", ".*"))) {
                            return false;
                        }
                    }
                    for (String protectedPath : jwtProperties.protectedPaths()) {
                        if (path.matches(protectedPath.replace("**", ".*"))) {
                            return false;
                        }
                    }
                    return true;
                })
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .build();
    }
}