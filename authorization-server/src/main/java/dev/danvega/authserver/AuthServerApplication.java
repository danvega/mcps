package dev.danvega.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * OAuth2 Authorization Server for Model Context Protocol (MCP).
 *
 * This server:
 * - Authenticates users via GitHub OAuth
 * - Issues JWTs for MCP clients
 * - Provides JWKS endpoint for JWT validation
 * - Implements MCP OAuth2 spec (RFC9728, Dynamic Client Registration, Resource Indicators)
 *
 * Runs on port 9000 (separate from MCP server on 8080)
 */
@SpringBootApplication
public class AuthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServerApplication.class, args);
	}

}
