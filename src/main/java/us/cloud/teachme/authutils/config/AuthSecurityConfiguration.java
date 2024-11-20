package us.cloud.teachme.authutils.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({JwtConfiguration.class, SecurityConfiguration.class})
public class AuthSecurityConfiguration {

}
