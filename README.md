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
   ├─ config.example.json
   ├─ serve.nu
   └─ README.md
```

## Quick Start

```bash
cd oauth/examples
cp config.example.json config.json
# Edit config.json with credentials
export OAUTH_CONFIG=config.json
nu -c "cat serve.nu | http-nu :8080 -"
```

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
3. Add to `examples/config.example.json`

## Dependencies

- [Nushell](https://www.nushell.sh)
- [http-nu](https://github.com/cablehead/http-nu)
