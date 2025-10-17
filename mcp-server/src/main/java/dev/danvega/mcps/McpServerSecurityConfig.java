package dev.danvega.mcps;

import org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class McpServerSecurityConfig {

    @Value("${authorization.server.url}")
    private String authServerUrl;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Allow public access to OAuth metadata for client discovery (RFC 9728)
                // All other requests require authentication
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/.well-known/oauth-protected-resource/**").permitAll()
                        .anyRequest().authenticated()
                )
                // Enable CORS for browser-based clients (MCP Inspector, etc.)
                .cors(Customizer.withDefaults())
                // Disable CSRF - not needed for stateless JWT-based APIs
                .csrf(csrf -> csrf.disable())
                // Configure OAuth2 on the MCP server
                .with(
                        McpServerOAuth2Configurer.mcpServerOAuth2(),
                        (mcpAuthorization) -> {
                            // REQUIRED: the authserver's issuer URI
                            mcpAuthorization.authorizationServer(this.authServerUrl);
                            // OPTIONAL: enforce the `aud` claim in the JWT token.
                            mcpAuthorization.validateAudienceClaim(true);
                        }
                )
                .build();
    }

    /**
     * CORS configuration for browser-based MCP clients (MCP Inspector, Claude Desktop, etc.)
     * Allows all origins in development. In production, restrict to specific origins.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Allow all origins for development (use specific origins in production)
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
