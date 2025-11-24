# OAuth Library for Nushell

Provider-agnostic OAuth 2.0 for Nushell with [http-nu](https://github.com/cablehead/http-nu).

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

**Discord:**
```bash
cd oauth/examples/discord-app
cp .env.example .env
# Edit .env with credentials from https://discord.com/developers/applications
# Leave "Public Client" unchecked, add redirect: http://localhost:8080/auth/callback
nu -c "with-env (open .env | lines | where {\$in | str contains '='} | parse '{key}={value}' | transpose -r | into record) { cat serve.nu | http-nu :8080 - }"
```

**Google:** Same steps, use `oauth/examples/google-app` and https://console.cloud.google.com/apis/credentials

## Provider Interface

```nushell
{
  auth-url: {|client: record state: string| string }
  token-exchange: {|client: record code: string| record }
  get-user: {|access_token: string| record }
  verify-token?: {|token: string| record }  # Optional
}
```

## Client Configuration

```nushell
{
  provider_name: "discord"
  id: string                # Client ID
  secret: string            # Client secret
  redirect: string          # Redirect URI
  scopes: list<string>      # OAuth scopes
  sessions: record          # Session store
  states: record            # State store
}
```

## API

- `oauth get-auth` - Get authenticated user from session
- `oauth handle-oauth` - Initiate OAuth flow
- `oauth handle-oauth-callback` - Process OAuth callback
- `oauth handle-logout` - Clear session
- `oauth generate-state` - Generate CSRF state token
- `oauth validate-state` - Validate state token

## Security Features

- CSRF protection with random state validation
- State tokens expire after 5 minutes and are single-use
- Session identifiers use SHA256 hashing
- Cookies: HttpOnly, SameSite=Lax, Secure (HTTPS)
- PKCE not implemented (planned)

## Adding Providers

1. Create `providers/your-provider/mod.nu` implementing the interface
2. Register in `providers/mod.nu`
3. Add example in `examples/`

## Dependencies

- [Nushell](https://www.nushell.sh)
- [http-nu](https://github.com/cablehead/http-nu)
