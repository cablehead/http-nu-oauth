# Multi-Provider OAuth Example

Single app supporting multiple OAuth providers.

## Setup

1. **Configure Providers**
   ```bash
   cp config.example.json config.json
   # Edit config.json with your credentials
   ```

2. **Get Credentials**
   - Discord: https://discord.com/developers/applications
   - Google: https://console.cloud.google.com/apis/credentials

3. **Run**
   ```bash
   export OAUTH_CONFIG=config.json
   nu -c "cat serve.nu | http-nu :8080 -"
   ```

4. **Visit** http://localhost:8080

## Flow

- Unauthenticated: Shows list of configured providers
- Click provider → OAuth flow → Shows user info from that provider
- Logout → Returns to provider list
