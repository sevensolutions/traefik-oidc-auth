---
sidebar_position: 2
---

# How this Plugin Works

The *Traefik OIDC Authentication* plugin secures upstream services by integrating OAuth 2.0 authentication directly into the Traefik reverse proxy. Acting as an authentication middleware, the plugin intercepts incoming requests and performs the following steps:

1. **Authentication Verification**  
Checks for the presence of a valid OAuth token, provided via Cookie.

2. **Token Validation**  
Verifies the token with the configured OAuth provider, ensuring it is valid and unexpired.

3. **User Authorization**  
Confirms that the authenticated user has the necessary permissions to access the upstream service. This may involve claim validation or matching user roles.

4. **Request Handling**  
If the token is valid, the plugin allows the request to pass through to the upstream service.
If the token is missing, invalid, or unauthorized, the plugin redirects the user to the OAuth provider's authorization endpoint or returns an HTTP error (e.g., 401 Unauthorized).

The plugin simplifies secure access to protected services, eliminating the need for individual applications to implement OAuth flows. It is especially useful for services running behind Traefik in microservices architectures. Configuration typically includes specifying the OAuth provider, client credentials, and allowed scopes or roles.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant User as User
    participant Traefik as Traefik (with traefik-oidc-auth Plugin)
    participant OAuth as OAuth Provider
    participant Service as Upstream Service

    alt Cookie missing
        User->>Traefik: Request to access service
        Traefik-->>User: Redirect to OAuth Provider for login
        User->>OAuth: Login and consent
        OAuth-->>User: Redirect to Traefik Callback
        User-->>Traefik: Follow Traefik Callback
        Traefik-->>OAuth: Exchange Code for Token
        OAuth-->>Traefik: Return Tokens
        Traefik->>Traefik: Validate Authorization
        alt Authorized
            Traefik-->>User: Redirect to requested page (Include Cookie)
        else Not Authorized
            Traefik-->>User: Return 401 Unauthorized
        end
    end
    alt Token present in request
        User->>Traefik: Request to access service
        Traefik-->>OAuth: Fetch JWKS
        OAuth-->>Traefik: JWKS
        Traefik->>Traefik: Validate Token and Authorization
        alt Token is valid
            Traefik->>Service: Forward request
            Service-->>Traefik: Response
            Traefik-->>User: Return service response
        else Token is invalid or expired
            Traefik-->>User: Redirect to OAuth Provider for login
        end
    end
```
