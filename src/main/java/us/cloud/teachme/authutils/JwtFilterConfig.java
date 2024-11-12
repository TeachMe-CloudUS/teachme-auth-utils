package us.cloud.teachme.authutils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Configuration
public class JwtFilterConfig {

    @Value("${jwt.public-key.path}")
    private Resource publicKeyResource;

    @Value("${jwt.protected-paths:/api/*}")
    private String[] protectedPaths;

    @Bean
    public JwtTokenValidator jwtTokenValidator() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        byte[] keyBytes = Files.readAllBytes(publicKeyResource.getFile().toPath());
        String publicKeyPem = new String(keyBytes)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        return new JwtTokenValidator(publicKeyPem);
    }

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilter() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtTokenValidator(), protectedPaths);
        FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(filter);
        registrationBean.addUrlPatterns(protectedPaths);
        return registrationBean;
    }
}
