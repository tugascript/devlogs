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
- Add support for multiple 2FA types

### IDP On-Going

- Add OAuth Dynamic Registration for:
  - accounts
  - apps
- Make refresh tokens whitelisted not blacklisted
- Add grants to control refresh token

### IDP Todo

- User authentication for each app type:
  - web
  - native & spa
  - backend
  - device
  - service
  - MCP
- Custom External Providers
- Account key generation
- Add Passkey (WebAuthn) support
- Dynamic OIDC configs
- Separate signing, encryption, and decryption into a KMS service

## Mailer

### Mailer Done

- Basic email queue

### Mailer On-Going

NONE

### Mailer Todo

- Change Queue from Redis to RabbitMQ
- Use templates instead of full emails

## KMS

### KMS Done

NONE

### KMS On-Going

NONE

### KMS Todo

- Add gRPC endpoints for KMS operations
- Add KMS mTLS authentication
- Add SEK, DEK, KEK generation
- Add SEK, DEK, KEK rotation
- Add SEK, DEK, KEK revocation
- Add SEK, DEK, KEK destruction
- Add DEK encryption & decryption
- Add JWKs generation & rotation
- Add JWKs revocation & destruction
- Add JWKs signing & verification
- Add JWKs public key retrieval

## Scripts

### Scripts Done

NONE

### Scripts On-Going

NONE

### Scripts Todo

- Add a revoked tokens cleanup script
- Add a expired JWKs cleanup script
- Add script to add root client JWKs for dynamic registration
