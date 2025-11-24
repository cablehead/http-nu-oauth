# Multi-Provider OAuth Example

Single app supporting multiple OAuth providers.

## Setup

1. **Get Credentials**

   **Discord:**
   1. Go to https://discord.com/developers/applications
   2. New Application → Name it → Create
   3. OAuth2 → Add redirect: `http://localhost:8080/auth/callback`
   4. Copy Client ID and Client Secret

   **Google:**
   1. Go to https://console.cloud.google.com/apis/credentials
   2. Create Project (if needed)
   3. Create Credentials → OAuth client ID → Web application
   4. Add authorized redirect URI: `http://localhost:8080/auth/callback`
   5. Copy Client ID and Client Secret
   6. Note: Scopes are configured in code, not in the console

2. **Configure**
   ```bash
   cp config.example.json config.json
   # Edit config.json with your credentials
   ```

3. **Run**
   ```nushell
   $env.OAUTH_CONFIG = open config.json | to json
   cat serve.nu | http-nu :8080 -
   ```

4. **Visit** http://localhost:8080

## Flow

- Unauthenticated: Shows list of configured providers
- Click provider → OAuth flow → Shows user info from that provider
- Logout → Returns to provider list
