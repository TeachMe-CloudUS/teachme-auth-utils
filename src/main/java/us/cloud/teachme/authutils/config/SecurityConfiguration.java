package us.cloud.teachme.authutils.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        String[] protectedPaths = jwtProperties.protectedPaths();
        if (protectedPaths == null || protectedPaths.length == 0) {
            return http
                    .csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .build();
        }

        return http
                .securityMatcher(jwtProperties.protectedPaths())
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers(jwtProperties.protectedPaths()).authenticated())
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(ex ->
                        ex.authenticationEntryPoint(jwtAuthEntryPoint))
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenValidator, jwtAuthEntryPoint), UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}