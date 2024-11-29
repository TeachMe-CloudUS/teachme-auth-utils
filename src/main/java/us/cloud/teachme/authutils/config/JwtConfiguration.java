package us.cloud.teachme.authutils.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import us.cloud.teachme.authutils.exception.JwtAuthenticationEntryPoint;
import us.cloud.teachme.authutils.service.JwtTokenValidator;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfiguration {

    @Value("${jwt.secret-key}")
    private String secretKey;

    @Bean
    public JwtTokenValidator jwtTokenValidator() {
        try {
            return new JwtTokenValidator(secretKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize JWT validator: " + e.getMessage(), e);
        }
    }

    @Bean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }
}
