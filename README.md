# OAuth Library for Nushell

Secure, provider-agnostic OAuth 2.0 library for Nushell applications using [http-nu](https://github.com/cablehead/http-nu).

## Features

- ✅ **CSRF Protection**: Cryptographically secure state validation
- ✅ **Multiple Providers**: Discord, Google (easily extensible)
- ✅ **Secure Cookies**: HttpOnly, SameSite, Secure flags
- ✅ **Provider Pattern**: Clean abstraction for OAuth providers
- ✅ **Session Management**: Filesystem-based session storage
- ✅ **Type Safe**: Leverages Nushell's type system

## Security

This library addresses common OAuth 2.0 vulnerabilities:

1. **CSRF Protection**: Uses cryptographically random state tokens with server-side validation
2. **Open Redirect Prevention**: Validates redirect URLs
3. **Secure Session Storage**: SHA256-hashed session identifiers
4. **One-time State Tokens**: State tokens expire after 5 minutes and are deleted after use
5. **Secure Cookies**: HttpOnly prevents XSS, SameSite prevents CSRF, Secure for HTTPS

## Structure

```
oauth/
├─ lib.nu                    # Common OAuth logic
├─ providers/
│  ├─ mod.nu                 # Provider registry
│  ├─ discord/mod.nu         # Discord OAuth
│  └─ google/mod.nu          # Google OAuth
└─ examples/
   ├─ discord-app/
   └─ google-app/
```

## Quick Start

### Discord Example

1. **Create Discord Application**
   - Go to https://discord.com/developers/applications
   - Create application → OAuth2 → Add redirect: `http://localhost:8080/auth/callback`
   - **Important**: Leave "Public Client" unchecked
   - Copy Client ID and Secret

2. **Setup**
   ```bash
   cd oauth/examples/discord-app
   cp .env.example .env
   # Edit .env with your credentials
   ```

3. **Run**
   ```bash
   nu -c "with-env (open .env | lines | where {\$in | str contains '='} | parse '{key}={value}' | transpose -r | into record) { cat serve.nu | http-nu :8080 - }"
   ```

4. **Visit** http://localhost:8080

### Google Example

Same steps, but use `oauth/examples/google-app` and get credentials from https://console.cloud.google.com/apis/credentials

## Provider Interface

Each provider implements:

```nushell
{
  # Build authorization URL
  auth-url: {|client: record state: string| string }

  # Exchange code for tokens
  token-exchange: {|client: record code: string| record }

  # Get user info from access token
  get-user: {|access_token: string| record }

  # Optional: Provider-specific features
  verify-token?: {|token: string| record }
}
```

## Adding New Providers

1. Create `providers/your-provider/mod.nu`
2. Implement provider interface
3. Register in `providers/mod.nu`
4. Add example app

See existing providers for reference.

## Client Configuration

Applications provide a client record:

```nushell
{
  provider_name: "discord"  # Provider identifier
  id: string                # OAuth client ID
  secret: string            # OAuth client secret
  redirect: string          # Redirect URI
  scopes: list<string>      # OAuth scopes
  sessions: record          # Session store
  states: record            # State store (for CSRF)
}
```

## API

### `oauth get-auth`
Get authenticated user from session cookie.

### `oauth handle-oauth`
Initiate OAuth flow (generates state, redirects to provider).

### `oauth handle-oauth-callback`
Process OAuth callback (validates state, exchanges code, stores session).

### `oauth handle-logout`
Clear session and cookie.

### `oauth generate-state`
Generate CSRF-safe state token.

### `oauth validate-state`
Validate state token (checks existence and expiration).

## Dependencies

- [Nushell](https://www.nushell.sh)
- [http-nu](https://github.com/cablehead/http-nu)

## OAuth 2.0 Best Practices

This library follows [OAuth 2.0 Security Best Current Practice (RFC)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-20):

- ✅ CSRF protection via state parameter
- ✅ Short-lived sessions
- ✅ Secure cookie flags
- ✅ One-time use state tokens
- ✅ HTTPS enforcement (production)
- ⚠️ PKCE not yet implemented (planned for OAuth 2.1 compliance)

## License

MIT
