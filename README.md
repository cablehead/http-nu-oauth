# OAuth Library for Nushell

Provider-agnostic OAuth 2.0 for Nushell with
[http-nu](https://github.com/cablehead/http-nu).

<div align="center">
  <video src="https://github.com/user-attachments/assets/8bab337e-cdcc-4731-aa58-908ae3f35f86"
         width="500"
         controls>
  </video>
</div>

## Structure

```
http-nu-oauth/
  lib.nu                    # Common OAuth logic
  providers/
    mod.nu                  # Provider registry
    discord/mod.nu          # Discord OAuth
    google/mod.nu           # Google OAuth
  examples/
    config.example.json
    serve.nu
    README.md
```

## Quick Start

```nushell
cd http-nu-oauth/examples
cp config.example.json config.json
# Edit config.json with credentials
$env.OAUTH_CONFIG = open config.json | to json
cat serve.nu | http-nu :8080 -
```

## Provider Interface

```nushell
{
  auth-url: {|client: record state: string| string }
  token-exchange: {|client: record code: string| record }
  get-user: {|access_token: string| record }
  token-refresh?: {|client: record refresh_token: string| record }  # Optional
  verify-token?: {|token: string| record }  # Optional
}
```

## API

- `get-auth` - Get authenticated user from session
- `handle-oauth` - Initiate OAuth flow
- `handle-oauth-callback` - Process OAuth callback
- `handle-logout` - Clear session
- `generate-state` - Generate CSRF state token
- `validate-state` - Validate state token
- `make-simplefile-store` - Create file-based key-value store

## Store Interface

```nushell
{
  set: {|| string }           # pipes content, returns hash
  get: {|hash: string| any }  # returns content or null
  update: {|hash: string| }   # pipes content, overwrites existing
  delete: {|hash: string| }
}
```

`make-simplefile-store "path"` returns a file-backed store. Swap for
redis/sqlite by matching the interface. Used for sessions (long-lived) and
states (ephemeral CSRF tokens).

## Tests

```nushell
nu test.nu
```

Uses fixtures in `fixtures/google/` and `fixtures/discord/` for isolated testing
without network calls.

## Security Features

- CSRF protection with random state validation
- State tokens expire after 5 minutes and are single-use
- Access tokens respect provider TTL and expire automatically
- Automatic token refresh using refresh_token when available
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
