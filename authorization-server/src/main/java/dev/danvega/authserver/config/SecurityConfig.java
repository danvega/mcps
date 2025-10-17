package dev.danvega.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration for GitHub federated login.
 *
 * This configuration:
 * - Enables OAuth2 login with GitHub as the identity provider
 * - Handles user authentication for the authorization server
 * - Runs after the authorization server security filter chain (Order 2)
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Default security filter chain for user authentication.
     * Order(2) ensures this runs after the authorization server endpoints filter chain.
     *
     * When a user needs to authenticate:
     * 1. Redirected to /oauth2/authorization/github (configured in AuthServerConfig)
     * 2. GitHub handles authentication
     * 3. User redirected back to /login/oauth2/code/github
     * 4. Spring Security processes the OAuth2 response
     * 5. User is authenticated and can authorize OAuth2 clients
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                )
                // Enable CORS for browser-based clients
                .cors(Customizer.withDefaults())
                // Enable OAuth2 login with GitHub
                .oauth2Login(Customizer.withDefaults());

        return http.build();
    }
}
