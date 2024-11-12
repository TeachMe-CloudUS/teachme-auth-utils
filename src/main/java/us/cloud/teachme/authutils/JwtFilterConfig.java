package us.cloud.teachme.authutils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

@Configuration
public class JwtFilterConfig {

    @Value("${jwt.public-key.path}")
    private Resource publicKeyResource;

    @Value("${jwt.protected-paths:/api/*}")
    private String[] protectedPaths;

    @Bean
    public JwtTokenValidator jwtTokenValidator() throws Exception {
        var publicKey = AuthenticationUtils.loadPublicKey(publicKeyResource.getFile().toPath());
        return new JwtTokenValidator(publicKey);
    }

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilter() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtTokenValidator(), protectedPaths);
        FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(filter);
        registrationBean.addUrlPatterns(protectedPaths);
        return registrationBean;
    }
}
