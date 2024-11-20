package us.cloud.teachme.authutils.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.util.Objects;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(Resource publicKeyPath, String[] protectedPaths) {
   public  JwtProperties {
       if (Objects.isNull(protectedPaths)) {
           protectedPaths = new String[]{};
       }
   }
}
