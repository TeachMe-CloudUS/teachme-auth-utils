package us.cloud.teachme.authutils.config;

import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(String secretKey, String[] protectedPaths) {
   public  JwtProperties {
       if (Objects.isNull(protectedPaths)) {
           protectedPaths = new String[]{};
       }
   }
}
