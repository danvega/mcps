# Secured MCP Server with Spring Authorization Server & GitHub OAuth

A complete enterprise-grade implementation of Model Context Protocol (MCP) server security using Spring AI 1.1.0-M3, 
Spring Authorization Server, and GitHub OAuth2. This project is based on the article and wonderful work of my colleague
Daniel Garnier-Moiroux 👋🏻

https://spring.io/blog/2025/09/30/spring-ai-mcp-server-security

## Architecture Overview

This project demonstrates the **standard enterprise OAuth2 architecture** with separated concerns:

```
┌─────────────┐
│   GitHub    │ (Identity Provider)
│   OAuth     │
└──────┬──────┘
       │ (2) User authenticates with GitHub
       ▼
┌────────────────────────┐
│  Authorization Server  │  (Port 9000)
│  - GitHub Federation   │  (1) MCP Client requests access
│  - Issues JWTs         │  (3) Issues JWT with GitHub identity
│  - JWKS endpoint       │
└──────┬─────────────────┘
       │ (4) Returns JWT
       ▼
┌─────────────┐      (5) Calls MCP with JWT
│ MCP Client  │─────────────────────────────►┌──────────────┐
│             │  Authorization: Bearer <JWT> │  MCP Server  │ (Port 8080)
└─────────────┘◄─────────────────────────────│  - Validates │
                (6) Returns MCP tool results │    JWT       │
                                             │  - Executes  │
                                             │    Tools     │
                                             └──────────────┘
```

## Project Structure

**Multi-Module Maven Project**

```
mcps/                              # Parent Project
├── pom.xml                        # Parent POM (packaging=pom, defines modules)
├── mvnw, mvnw.cmd                 # Maven wrapper (shared by all modules)
├── .mvn/                          # Maven configuration
│
├── mcp-server/                    # Module 1: MCP Server (port 8080)
│   ├── pom.xml                    # Inherits from parent
│   └── src/main/
│       ├── java/dev/danvega/mcps/
│       │   ├── Application.java
│       │   ├── McpServerSecurityConfig.java # JWT validation
│       │   └── McpToolsService.java         # Secured MCP tools
│       └── resources/
│           └── application.properties
│
├── authorization-server/          # Module 2: Authorization Server (port 9000)
│   ├── pom.xml                    # Inherits from parent
│   └── src/main/
│       ├── java/dev/danvega/authserver/
│       │   ├── AuthServerApplication.java
│       │   └── config/
│       │       ├── AuthServerConfig.java    # OAuth2 server & MCP support
│       │       ├── SecurityConfig.java      # GitHub federated login
│       │       └── JwtCustomizer.java       # Add GitHub claims to JWT
│       └── resources/
│           └── application.yml
│
└── README.md                      # This file
```

### Maven Multi-Module Benefits

✅ Single command builds both modules
✅ Shared dependency versions (no conflicts)
✅ IDE recognizes both modules properly
✅ Standard enterprise Maven structure
✅ Centralized dependency management

## Prerequisites

- Java 25 (or adjust `java.version` in pom.xml)
- Maven 3.6+
- GitHub account for OAuth

## Setup Instructions

### 1. Create GitHub OAuth Apps

You need **TWO** separate GitHub OAuth Apps:

#### A. Authorization Server OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **"New OAuth App"**
3. Fill in:
   - **Application name**: MCP Authorization Server
   - **Homepage URL**: `http://localhost:9000`
   - **Authorization callback URL**: `http://localhost:9000/login/oauth2/code/github`
4. Click **"Register application"**
5. Note the **Client ID**
6. Generate **Client Secret** and save it

#### B. Register MCP Server as OAuth2 Client

The MCP server is pre-registered in the Authorization Server code with:
- **Client ID**: `mcp-server`
- **Client Secret**: `secret`
- **Redirect URIs**: `http://localhost:8080/login/oauth2/code/mcp`, `http://localhost:8080/authorized`

### 2. Configure Environment Variables

Create a `.env` file in the project root (already in `.gitignore`):

```bash
# GitHub OAuth (for Authorization Server)
GITHUB_CLIENT_ID=your-authorization-server-github-client-id
GITHUB_CLIENT_SECRET=your-authorization-server-github-client-secret

# Authorization Server URL (for MCP Server)
AUTHORIZATION_SERVER_URL=http://localhost:9000
```

Or export them:

```bash
export GITHUB_CLIENT_ID="your-authorization-server-github-client-id"
export GITHUB_CLIENT_SECRET="your-authorization-server-github-client-secret"
export AUTHORIZATION_SERVER_URL="http://localhost:9000"
```

### 3. Build the Project

**From the root directory**, build both modules:

```bash
# Build entire multi-module project (builds both auth server and MCP server)
./mvnw clean install
```

This single command:
- Builds the parent POM
- Builds the authorization-server module
- Builds the mcp-server module
- Runs all tests

### 4. Run the Services

Open **two terminal windows**:

#### Terminal 1: Start Authorization Server (port 9000) - **Start this FIRST**

```bash
# Run from root directory using -pl (project list)
./mvnw spring-boot:run -pl authorization-server
```

Wait for: `Started AuthServerApplication in X seconds`

**Important**: The authorization server **must be running** before starting the MCP server, as the MCP server validates JWTs using the auth server's JWKS endpoint.

#### Terminal 2: Start MCP Server (port 8080) - **Start this SECOND**

```bash
# Run from root directory
./mvnw spring-boot:run -pl mcp-server
```

Wait for: `Started Application in X seconds`

#### Alternative: Run from Module Directories

```bash
# Terminal 1: Auth Server
cd authorization-server
../mvnw spring-boot:run

# Terminal 2: MCP Server
cd mcp-server
../mvnw spring-boot:run
```

## Complete OAuth2 Flow

### Flow Diagram

```
1. Client: GET /mcp/tools/echo (no token)
   Server: 401 Unauthorized
   Header: WWW-Authenticate: Bearer realm="http://localhost:9000"

2. Client: Discovers auth server metadata
   GET http://localhost:9000/.well-known/oauth-authorization-server
   Response: {authorization_endpoint, token_endpoint, jwks_uri, ...}

3. Client: Initiates authorization code flow
    
    - http :8080/oauth2/authorize response_type==code client_id==mcp-server redirect_uri==http://localhost:8080/authorized scope=="openid profile email mcp.server" code_challenge=="<PKCE challenge>" code_challenge_method==S256
    - curl "http://localhost:8080/oauth2/authorize?response_type=code&client_id=mcp-server&redirect_uri=http://localhost:8080/authorized&scope=openid%20profile%20email%20mcp.server&code_challenge=<PKCE challenge>&code_challenge_method=S256"
    

4. Auth Server: Redirects to GitHub login
   User authenticates with GitHub
   GitHub redirects back to auth server
   Auth server redirects to client with authorization code

5. Client: Exchanges code for JWT
   POST /oauth2/token
   Body: {
       grant_type: authorization_code,
       code: <authorization code>,
       redirect_uri: http://localhost:8080/authorized,
       client_id: mcp-server,
       client_secret: secret,
       code_verifier: <PKCE verifier>
   }
   Response: {access_token: <JWT>, refresh_token: ..., expires_in: 900}

6. Client: Calls MCP endpoint with JWT
   GET /mcp/tools/echo?message=Hello
   Header: Authorization: Bearer <JWT>
   Server: Validates JWT, returns response
```

## Testing the Complete Flow

### Option 1: Manual Testing with cURL (Simplified)

1. **Get Authorization Code** (requires browser):

   Open in browser:
   ```
   http://localhost:9000/oauth2/authorize?response_type=code&client_id=mcp-server&redirect_uri=http://localhost:8080/authorized&scope=openid%20profile%20email%20mcp.server
   ```

   - You'll be redirected to GitHub to login
   - After login, you'll be redirected to `http://localhost:8080/authorized?code=XXXXX`
   - Copy the `code` parameter from the URL

2. **Exchange Code for JWT**:

   ```bash
   curl -X POST http://localhost:9000/oauth2/token \
     -u mcp-server:secret \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code" \
     -d "code=PASTE_CODE_HERE" \
     -d "redirect_uri=http://localhost:8080/authorized"
   ```

   Response:
   ```json
   {
     "access_token": "eyJhbGc...",
     "refresh_token": "...",
     "scope": "openid profile email mcp.server",
     "token_type": "Bearer",
     "expires_in": 899
   }
   ```

   Copy the `access_token`

3. **Call MCP Endpoints**:

   ```bash
   # Set token variable
   TOKEN="eyJhbGc..."

   # Echo tool
   curl http://localhost:8080/mcp/tools/echo \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"message": "Hello, secured MCP!"}'

   # Get current user
   curl http://localhost:8080/mcp/tools/getCurrentUser \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json"

   # Calculator
   curl http://localhost:8080/mcp/tools/calculate \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"operation": "add", "a": 10, "b": 5}'

   # Text processor
   curl http://localhost:8080/mcp/tools/textProcessor \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"text": "Hello World", "operation": "uppercase"}'
   ```

### Option 2: Automated Testing Script

Create a test script `test-mcp-oauth.sh`:

```bash
#!/bin/bash

# Colors for output
GREEN='\033[0.32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Testing MCP OAuth2 Flow..."
echo "Note: You need to manually get the authorization code first"
echo ""
echo "1. Open browser to:"
echo "   http://localhost:9000/oauth2/authorize?response_type=code&client_id=mcp-server&redirect_uri=http://localhost:8080/authorized&scope=openid%20profile%20email%20mcp.server"
echo ""
echo "2. After GitHub login, copy the 'code' parameter from the redirect URL"
echo ""
read -p "Enter the authorization code: " AUTH_CODE

# Exchange code for token
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:9000/oauth2/token \
  -u mcp-server:secret \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=http://localhost:8080/authorized")

# Extract access token
ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
    echo -e "${RED}Failed to get access token${NC}"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

echo -e "${GREEN}Got access token!${NC}"
echo ""

# Test MCP endpoints
echo "Testing echo endpoint..."
curl -s http://localhost:8080/mcp/tools/echo \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello, secured MCP!"}' | jq .

echo ""
echo "Testing getCurrentUser endpoint..."
curl -s http://localhost:8080/mcp/tools/getCurrentUser \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" | jq .
```

Make executable and run:
```bash
chmod +x test-mcp-oauth.sh
./test-mcp-oauth.sh
```

## Available MCP Tools

All tools require a valid JWT Bearer token:

### 1. Echo Tool
```bash
POST /mcp/tools/echo
{"message": "Hello"}
```

### 2. Calculator
```bash
POST /mcp/tools/calculate
{"operation": "add", "a": 10, "b": 5}
```
Operations: `add`, `subtract`, `multiply`, `divide`

### 3. Current User
```bash
POST /mcp/tools/getCurrentUser
{}
```
Returns authenticated user info from JWT claims

### 4. Server Status (Admin Only)
```bash
POST /mcp/tools/getServerStatus
{}
```
Requires `SCOPE_admin` or `ROLE_ADMIN` in JWT

### 5. Text Processor
```bash
POST /mcp/tools/textProcessor
{"text": "Hello World", "operation": "uppercase"}
```
Operations: `uppercase`, `lowercase`, `reverse`, `length`, `wordcount`

### 6. GitHub User
```bash
POST /mcp/tools/getGitHubUser
{"username": "octocat"}
```
Simulated GitHub API integration

## Authorization Server Endpoints

### OAuth2 & OIDC Endpoints

- **Authorization Endpoint**: `http://localhost:9000/oauth2/authorize`
- **Token Endpoint**: `http://localhost:9000/oauth2/token`
- **JWKS (Public Keys)**: `http://localhost:9000/oauth2/jwks`
- **Token Introspection**: `http://localhost:9000/oauth2/introspect`
- **Token Revocation**: `http://localhost:9000/oauth2/revoke`
- **Authorization Server Metadata**: `http://localhost:9000/.well-known/oauth-authorization-server`
- **OIDC Configuration**: `http://localhost:9000/.well-known/openid-configuration`
- **UserInfo**: `http://localhost:9000/userinfo`

### Check JWKS Endpoint

```bash
curl http://localhost:9000/oauth2/jwks | jq .
```

### Decode JWT Token

Use [jwt.io](https://jwt.io) to decode and inspect JWT tokens. You'll see:

```json
{
  "sub": "github-username",
  "aud": ["http://localhost:8080", "mcp-server"],
  "iss": "http://localhost:9000",
  "exp": 1234567890,
  "iat": 1234567000,
  "scope": "openid profile email mcp.server",
  "github_login": "username",
  "email": "user@example.com",
  "name": "User Name",
  "avatar_url": "https://avatars.githubusercontent.com/...",
  "profile_url": "https://github.com/username"
}
```

## Security Features

### Authorization Server
- **GitHub Federated Identity**: Users authenticate via GitHub OAuth
- **JWT Token Issuance**: Issues RFC 9068 compliant JWT access tokens
- **PKCE Required**: Enforces Proof Key for Code Exchange for security
- **Short-Lived Tokens**: Access tokens expire in 15 minutes
- **Refresh Tokens**: 1-day validity, non-reusable for security
- **JWKS Endpoint**: Public keys for JWT validation
- **MCP OAuth2 Compliance**: Implements RFC9728, Resource Indicators

### MCP Server
- **JWT Validation**: Validates all JWTs using JWKS from auth server
- **Audience Claim Validation**: Ensures tokens are issued for this server
- **Method-Level Security**: `@PreAuthorize` for fine-grained access control
- **Scope-Based Authorization**: Tools can require specific scopes
- **Stateless**: No server-side session storage
- **CORS**: Configured for cross-origin MCP clients

## Troubleshooting

### "Invalid token" or 401 Unauthorized

**Cause**: JWT token is invalid, expired, or not issued for this server

**Solutions**:
1. Check authorization server is running on port 9000
2. Verify `authorization.server.url=http://localhost:9000` in MCP server config
3. Check token hasn't expired (15-minute lifetime)
4. Verify audience claim includes `http://localhost:8080` or `mcp-server`
5. Get a fresh token using the OAuth2 flow

### GitHub OAuth redirect not working

**Cause**: OAuth app callback URL mismatch

**Solutions**:
1. Verify GitHub OAuth App callback: `http://localhost:9000/login/oauth2/code/github`
2. Check `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are set correctly
3. Ensure authorization server is running on port 9000

### "Client authentication failed"

**Cause**: Wrong client credentials

**Solutions**:
1. Use client_id: `mcp-server` and client_secret: `secret`
2. Send credentials via Basic Auth: `-u mcp-server:secret`
3. Or in request body: `client_id=mcp-server&client_secret=secret`

### Can't access auth server metadata

**Cause**: Authorization server not running or wrong URL

**Solutions**:
```bash
# Check if auth server is running
curl http://localhost:9000/.well-known/oauth-authorization-server

# Check auth server logs for errors
cd authorization-server
../mvnw spring-boot:run
```

### CORS errors from browser

**Cause**: MCP server CORS not configured for your origin

**Solution**: Update `McpServerSecurityConfig.corsConfigurationSource()` to include your client's origin

## Production Considerations

### Security Hardening

1. **Use HTTPS**: Both servers must use HTTPS in production
2. **Secure Client Secrets**: Store in HashiCorp Vault, AWS Secrets Manager, etc.
3. **Key Management**: Load RSA keys from secure keystore, not generated at runtime
4. **Token Lifetimes**: Adjust based on security requirements
5. **Audience Validation**: Ensure strict audience claim checking
6. **Rate Limiting**: Add rate limiting to prevent abuse
7. **Logging & Monitoring**: Track all authentication/authorization events

### Scalability

1. **Database-Backed Client Registry**: Replace `InMemoryRegisteredClientRepository`
2. **Token Storage**: Use Redis or database for token storage
3. **Load Balancing**: Deploy multiple instances behind load balancer
4. **Session Management**: Use sticky sessions or shared session store

### Configuration

Update production URLs in:
- Authorization server `issuer` setting
- MCP server `authorization.server.url`
- JWT `aud` claim validation
- GitHub OAuth callback URLs

## MCP Annotations Reference

MCP tools use annotations from `org.springaicommunity.mcp.annotation`:

```java
@McpTool(name = "toolName", description = "Tool description")
public ReturnType toolMethod(
    @McpToolParam(description = "Parameter description", required = true) String param
) {
    // implementation
}
```

## References

- [Spring Authorization Server Docs](https://docs.spring.io/spring-authorization-server/reference/)
- [Spring AI MCP Documentation](https://docs.spring.io/spring-ai/reference/1.1/api/mcp/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [Spring AI Community MCP Security](https://github.com/spring-ai-community/mcp-security)
- [OAuth 2.1 Specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [RFC 9068: JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068.html)
- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html)

## License

This is a demonstration project for educational purposes.
