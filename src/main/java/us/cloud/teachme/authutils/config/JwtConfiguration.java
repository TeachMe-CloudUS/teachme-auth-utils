package us.cloud.teachme.authutils.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import us.cloud.teachme.authutils.exception.JwtAuthenticationEntryPoint;
import us.cloud.teachme.authutils.service.JwtKeyLoader;
import us.cloud.teachme.authutils.service.JwtTokenValidator;

import java.security.PublicKey;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfiguration {

    @Bean
    public JwtTokenValidator jwtTokenValidator(JwtProperties properties) {
        try {
            PublicKey publicKey = JwtKeyLoader.loadPublicKey(properties.publicKeyPath());
            return new JwtTokenValidator(publicKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize JWT validator: " + e.getMessage(), e);
        }
    }

    @Bean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }
}
