package us.cloud.teachme.authutils.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Objects;

@ConfigurationProperties(prefix = "security.jwt")
public record JwtProperties(String secretKey, String[] protectedPaths, String[] whiteListedPaths) {
    public JwtProperties {
        if (Objects.isNull(protectedPaths)) {
            protectedPaths = new String[]{};
        }
        if (Objects.isNull(whiteListedPaths)) {
            whiteListedPaths = new String[]{};
        }
    }
}
