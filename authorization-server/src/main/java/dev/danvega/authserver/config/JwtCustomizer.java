package dev.danvega.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;

/**
 * OPTIONAL: JWT Token Customizer - adds user information to issued JWTs.
 *
 * This is NOT required for basic OAuth2/MCP functionality, but it's useful if you want to:
 * - Add the authenticated user's GitHub username, email, etc. to the JWT
 * - Access user information in your MCP server without additional API calls
 *
 * You can delete this entire file if you don't need custom claims.
 */
@Configuration
public class JwtCustomizer {

    /**
     * Adds audience claim and GitHub user information to JWT access tokens.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            // Only customize access tokens
            if (context.getTokenType().getValue().equals("access_token")) {

                // Add audience claim for MCP server validation
                context.getClaims().claim("aud", List.of(
                    "http://localhost:8080",  // MCP server URL
                    "mcp-server"              // MCP server client ID
                ));

                // If authenticated via GitHub OAuth, add GitHub user claims
                var authentication = context.getPrincipal();
                if (authentication instanceof OAuth2AuthenticationToken oauth2Auth) {
                    var userAttributes = oauth2Auth.getPrincipal().getAttributes();

                    // Add GitHub username as subject
                    if (userAttributes.containsKey("login")) {
                        context.getClaims().subject(userAttributes.get("login").toString());
                        context.getClaims().claim("github_login", userAttributes.get("login"));
                    }

                    // Add optional user profile information
                    if (userAttributes.containsKey("email")) {
                        context.getClaims().claim("email", userAttributes.get("email"));
                    }
                    if (userAttributes.containsKey("name")) {
                        context.getClaims().claim("name", userAttributes.get("name"));
                    }
                }
            }
        };
    }
}
