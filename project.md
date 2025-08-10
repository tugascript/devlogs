# Project Status

## IDP

### IDP Done

- Account standard authentication
- Multiple secrets Account Keys
- Fix all outstanding errors
- Accounts fix standard authentication
- Test account standard authentication & account operations
- Test multiple secrets account credentials
- Account KEK openbao integration
- Account KEK rotation & DEK re-encryption
- Accounts m2m auth:
  - client_credentials
  - jwt
- Remove Local Cache & Wipe Secrets from memory after use
- Multiple app types creation
  - web
  - native
  - spa
  - backend
  - device
  - service
  - mcp

### IDP On-Going

- Add OAuth Dynamic Registration for:
  - accounts
  - apps

### IDP Todo

- Account key generation
- Dynamic OIDC configs
- User authentication for each app type:
  - web
  - native & spa
  - backend
  - device
  - service
  - MCP

## Mailer

### Mailer Done

- Basic email queue

### Mailer On-Going

NONE

### Mailer Todo

- Change Queue from Redis to RabbitMQ
- Use templates instead of full emails

## Scripts

### Scripts Done

NONE

### Scripts On-Going

NONE

### Scripts Todo

- Add a revoked tokens cleanup script
- Add a expired JWKs cleanup script
- Add script to add root client JWKs for dynamic registration
