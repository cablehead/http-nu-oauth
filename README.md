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
- `make-xs-store` - Create cross.stream-backed key-value store

## Storage Interface

A store is a record of closures. The key is minted by the store (callers never
choose it) and the value is an opaque string (callers store JSON):

```nushell
{
  set:    {|| string }          # pipe value in; returns a fresh KEY
  get:    {|key: string| any }  # returns the stored value, or null
  update: {|key: string| }      # pipe value in; overwrites value at KEY
  delete: {|key: string| }      # removes KEY
  sweep:  {|| }                 # GC expired entries (no-op without a ttl)
}
```

**Contract**

- **Key format** — keys are opaque 64-char lowercase-hex tokens
  (`^[a-f0-9]{64}$`). Callers must treat them as opaque.
- **Key validation (load-bearing)** — keys arrive straight from an
  attacker-controlled cookie, so implementations MUST validate the key shape at
  the `get`/`update`/`delete` boundary and treat any malformed key as absent.
  This is what prevents path traversal (file impl) and topic injection (xs
  impl).
- **Return types** — `get` returns the stored string, or `null` when the key is
  absent, malformed, or expired. `set` returns the new key. `update`/`delete`
  return nothing.
- **Error behavior** — `get`/`update`/`delete` on an absent or malformed key
  never throw: `get` yields `null`, `update`/`delete` are no-ops.
- **TTL** — a store may be created with a TTL for ephemeral entries (CSRF
  states). Entries past their TTL read as `null`.

**Implementations**

- `make-simplefile-store "path" [--ttl <duration>]` — file-backed. Keys are
  SHA256 digests used as filenames; atomic raw reads/writes; `--ttl` lazily
  expires stale files on read and sweeps on write.
- `make-xs-store "base" [--ttl <xs-ttl>]` — [cross.stream](https://cross.stream)
  backed. Each entry is a topic `<base>.<key>` whose latest frame is the value
  (content in CAS). Long-lived stores keep only the current value per key
  (`--ttl last:1`); ephemeral stores use a native frame ttl (e.g.
  `--ttl "time:300000"`) so states expire on their own — no manual sweep.
  Requires the xs store commands, i.e. run under `http-nu --store <dir>`.

Both implementations satisfy the same contract and are verified by the same
table-driven suite (`test-contract.nu`), run against both.

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
