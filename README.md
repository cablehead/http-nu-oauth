# http-nu-oauth

OAuth 2.0 login for [http-nu](https://github.com/cablehead/http-nu) apps,
written in [Nushell](https://www.nushell.sh). You get a small set of request
handlers that run the provider redirect dance, keep a cookie session, and hand
you back the logged-in user — plus an allowlist helper to gate the actions that
matter.

Discord and Google are included; adding a provider is one small file.

<div align="center">
  <video src="https://github.com/user-attachments/assets/8bab337e-cdcc-4731-aa58-908ae3f35f86"
         width="500"
         controls>
  </video>
</div>

## How it works

```
browser ──GET /auth/login/discord──▶ handle-oauth ─302─▶ provider consent screen
provider ──GET /auth/callback?code&state──▶ handle-oauth-callback ─set cookie─▶ browser
browser ──(any request, carries the cookie)──▶ get-auth ─▶ {user, provider, …} | null
```

- **Sessions** are long-lived. On a successful login the library stores the
  session and sets an opaque cookie; `get-auth` turns that cookie back into the
  user on every request.
- **States** are the short-lived, single-use CSRF tokens that protect the
  redirect round-trip. They expire on their own (default 5 min).
- Both live in a pluggable **store** — file-backed out of the box, or
  [cross.stream](https://cross.stream). Same interface either way.
- You decide who can do what with an **allowlist** keyed on the provider's
  immutable user ID.

This library backs logins where an allowlist gates destructive actions, so auth
correctness is load-bearing — see [Security](#security).

## Quick start

Run the multi-provider example:

```nushell
cd examples
cp config.example.json config.json      # then add your client id/secret
$env.OAUTH_CONFIG = open config.json | to json
cat serve.nu | http-nu :8080 -
```

Visit http://localhost:8080. See [`examples/README.md`](examples/README.md) for
getting Discord/Google credentials. Redirect URI is
`http://localhost:8080/auth/callback`.

## Using it in your app

Your http-nu script is one request-handling closure. Build a **client** record
(credentials + a session store + a state store), then route the auth endpoints
to the handlers and gate whatever you like with `is-allowed`:

```nushell
use lib.nu *
use providers

# Immutable provider user IDs allowed to do privileged things.
const ADMINS = ["80351110224678912"]

def client [provider_name: string] {
  {
    provider_name: $provider_name
    id: "…client id…"
    secret: "…client secret…"
    redirect: "http://localhost:8080/auth/callback"
    scopes: ["identify"]
    sessions: (make-file-store "sessions")                 # persistent
    states:   (make-file-store "states" --ttl $STATE_TTL)  # expiring
  }
}

{|req|
  match $req {
    # 1. Start login → redirect to the provider
    {method: "GET", path: $p} if ($p | str starts-with "/auth/login/") => {
      let name = $p | str replace "/auth/login/" ""
      handle-oauth (providers all | get $name) (client $name) "/"
    }

    # 2. Provider redirects back with ?code & ?state → set session cookie
    {method: "GET", path: "/auth/callback"} => {
      # (the example reads the provider name back out of the state cookie)
      handle-oauth-callback (providers all | get discord) (client "discord") $req
    }

    # 3. Logout — requires the per-session csrf token (see below)
    {method: "GET", path: "/auth/logout"} => { handle-logout (client "discord") $req }

    # 4. Anything else → who is this?
    _ => {
      let auth = get-auth (client "discord") $req (providers all)
      if ($auth | is-empty) {
        "not logged in"
      } else if (is-allowed $auth.provider $auth.user $ADMINS) {
        "welcome, admin — you may deploy"
      } else {
        $"hi ($auth.user.username? | default $auth.user.email?)"
      }
    }
  }
}
```

[`examples/serve.nu`](examples/serve.nu) is the complete, runnable version
(multi-provider, HTML pages, CSRF-tokenised logout link).

## API

**Flow handlers** (each returns an http-nu `.response`):

| Function | Purpose |
| -------- | ------- |
| `handle-oauth <provider> <client> <return_to>` | Start the flow; 302 to the provider |
| `handle-oauth-callback <provider> <client> <req>` | Validate state, exchange code, set session cookie, redirect to `return_to` |
| `handle-logout <client> <req>` | Clear the session (requires a valid `?csrf=` token) |
| `get-auth <client> <req> <providers>` | Resolve the cookie to `{user, provider, …}`, or `null`. Honors the provider's token TTL (refreshes or evicts) |

**Authorization**

| Function | Purpose |
| -------- | ------- |
| `is-allowed <provider> <user> <allowlist>` | Is this user's immutable ID on the allowlist? |
| `account-id <provider> <user>` | The immutable ID to key on (Discord `id`; Google `sub`, only if `email_verified`), or `null` |
| `safe-return-to <path>` | Clamp a post-login redirect to a same-origin path |

**CSRF state**

| Function | Purpose |
| -------- | ------- |
| `generate-state <return_to> <provider_name>` | Mint a state token + its stored data |
| `validate-state <token> <states> [--ttl]` | Check match + single-use + TTL (`STATE_TTL`, default `5min`) |

**Stores** — `make-file-store`, `make-xs-store` (see below).

## Provider interface

A provider is a record of closures. To add one, drop
`providers/your-name/mod.nu` implementing this and register it in
`providers/mod.nu`:

```nushell
{
  auth-url:       {|client: record, state: string| string }  # authorization URL
  token-exchange: {|client: record, code: string| record }   # code → token response
  get-user:       {|access_token: string| record }           # token → { status, body }
  token-refresh?: {|client: record, refresh_token: string| record }  # optional
  verify-token?:  {|token: string| record }                  # optional
}
```

## Storage interface

A store is a record of closures. The store mints the key (callers never choose
it); the value is an opaque string (store JSON):

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

- **Key format** — opaque 64-char lowercase-hex tokens (`^[a-f0-9]{64}$`).
- **Key validation (load-bearing)** — keys arrive straight from a cookie, so an
  implementation MUST validate the key shape at the `get`/`update`/`delete`
  boundary and treat anything malformed as absent. This is what blocks path
  traversal (file) and topic injection (xs).
- **Returns** — `get` → the stored string, or `null` when the key is absent,
  malformed, or expired. `set` → the new key. `update`/`delete` → nothing.
- **Errors** — `get`/`update`/`delete` on an absent or malformed key never
  throw: `get` yields `null`, the others are no-ops.
- **TTL** — pass `--ttl <duration>` for an **expiring** store (states); omit it
  for a **persistent** store (sessions). Expired entries read as `null`.

**Implementations**

- `make-file-store "path" [--ttl <duration>]` — file-backed. Keys are SHA256
  digests used as filenames; raw atomic reads/writes; `--ttl` expires stale
  files on read and sweeps on write.
- `make-xs-store "base" [--ttl <duration>]` —
  [cross.stream](https://cross.stream)-backed. Each entry is a topic
  `<base>.<key>` whose latest frame is the value (content in CAS). Persistent
  stores keep only the current value per key (`last:1`); expiring stores
  translate `--ttl` to a native frame ttl (`time:<ms>`), so entries expire
  themselves — no sweep. Needs the xs store commands, i.e. run under
  `http-nu --store <dir>`.

Both satisfy the same contract and are checked by the same table-driven suite
(`test-contract.nu`), run against both.

## Security

Auth here gates real actions, so the defenses are enforced in code and covered
by tests, not just documented:

- **Store key validation** — cookie-supplied keys are validated
  (`^[a-f0-9]{64}$`) at the store boundary, blocking path traversal (file) and
  topic injection (xs). A bad key reads as absent.
- **CSRF state** — random token, validated on callback, single-use, with a
  configurable `STATE_TTL` (default 5 min). This is our policy, separate from
  session lifetime.
- **Bounded state store** — expired states are reclaimed (file sweeps / xs
  native TTL), so they can't accumulate into a disk-exhaustion DoS.
- **CSRF-protected logout** — `/auth/logout` needs a per-session token, so a
  cross-site request can't force a logout.
- **Open-redirect protection** — the post-login `return_to` is clamped to a
  same-origin path (rejects absolute URLs and `//host` / `/\host`).
- **Provider session TTL** — sessions respect `expires_in`; an expired session
  is refreshed via `refresh_token` when possible, otherwise evicted. Session
  IDs are SHA256 digests.
- **Allowlist on immutable IDs** — authorization keys on provider-issued IDs
  (Discord `id`, Google `sub` + `email_verified`), never a username or email
  (those change and can be reassigned).
- **JWT trust boundary** — the Google `id_token` is only decoded from
  token-endpoint output; unsigned (`alg=none`) and malformed tokens are
  rejected. See the note in `providers/google/mod.nu`.
- **Cookies** — HttpOnly, SameSite=Lax, Secure (over HTTPS).
- PKCE is not implemented yet (planned).

## Project layout

```
lib.nu                 # handlers, stores, state, allowlist — the library
providers/
  mod.nu               # registry (providers all)
  discord/mod.nu
  google/mod.nu
examples/
  serve.nu             # complete runnable multi-provider app
  config.example.json
test.nu                # unit + security tests
test-contract.nu       # shared store-contract suite (file + xs)
fixtures/              # provider fixtures for offline tests
```

## Testing

```nushell
nu test.nu
```

Runs the unit and security tests plus the store-contract suite against both
store implementations, using `fixtures/` so no network is touched. (The xs
contract runs via `http-nu eval --store`, so `http-nu` must be on `PATH`.)

## Requirements

- [Nushell](https://www.nushell.sh)
- [http-nu](https://github.com/cablehead/http-nu)
- [cross.stream](https://cross.stream) — only if you use `make-xs-store`
</content>
</invoke>
