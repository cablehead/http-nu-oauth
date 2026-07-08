#!/usr/bin/env nu
# OAuth Library Tests
# Run with: nu test.nu

use lib.nu *
use providers

def main [] {
  test-exports
  test-store
  test-google-jwt
  test-session-expiry
  test-session-expiry-enforced
  test-store-key-validation
  test-traversal-delete
  test-traversal-auth-bypass
  test-validate-state
  test-store-ttl
  test-safe-return-to
  test-logout-csrf
  test-allowlist
  test-jwt-alg-none
  test-store-contract
}

def test-exports [] {
  # lib.nu exports
  let _ = (make-file-store "test-tmp" | describe)
  let _ = (generate-state "/" "test" | describe)
  let _ = (parse-cookies | describe)

  # providers
  let all_providers = providers all
  assert ($all_providers | get google? | is-not-empty) "google provider missing"
  assert ($all_providers | get discord? | is-not-empty) "discord provider missing"

  rm -rf test-tmp
  print "ok exports"
}

def test-store [] {
  let store = make-file-store "test-store"

  # set
  let content = '{"test": "data"}'
  let hash = $content | do $store.set
  assert (($hash | str length) > 0) "hash should not be empty"

  # get
  let retrieved = do $store.get $hash
  assert ($retrieved == $content) "retrieved content should match"

  # update
  let updated = '{"test": "updated"}'
  $updated | do $store.update $hash
  let retrieved2 = do $store.get $hash
  assert ($retrieved2 == $updated) "updated content should match"

  # delete
  do $store.delete $hash
  let deleted = do $store.get $hash
  assert ($deleted | is-empty) "deleted content should be empty"

  rm -rf test-store
  print "ok store"
}

def test-google-jwt [] {
  let fixture = open fixtures/google/token-response.json
  let provider = providers all | get google

  # get-user decodes the JWT
  let user_resp = do $provider.get-user $fixture.id_token

  assert ($user_resp.status == 200) "status should be 200"
  assert ($user_resp.body.email == "test@example.com") "email should match"
  assert ($user_resp.body.iss == "https://accounts.google.com") "issuer should match"

  print "ok google-jwt"
}

def test-session-expiry [] {
  let store = make-file-store "test-sessions"

  # Create a session that's NOT expired (issued now, expires in 1 hour)
  let valid_session = {
    access_token: "test"
    expires_in: 3600
    token_issued_at: (date now)
    user: {email: "test@example.com"}
    provider: "google"
  }
  let hash = $valid_session | to json -r | do $store.set

  # Read it back and check expiry
  let session = do $store.get $hash | from json
  let issued_at = $session.token_issued_at | into datetime
  let expires_at = $issued_at + ($session.expires_in * 1sec)
  let now = date now

  assert ($now < $expires_at) "session should not be expired"

  # Create an expired session (issued 2 hours ago, expired after 1 hour)
  let expired_session = {
    access_token: "test"
    expires_in: 3600
    token_issued_at: ((date now) - 2hr)
    user: {email: "test@example.com"}
    provider: "google"
  }
  let hash2 = $expired_session | to json -r | do $store.set

  let session2 = do $store.get $hash2 | from json
  let issued_at2 = $session2.token_issued_at | into datetime
  let expires_at2 = $issued_at2 + ($session2.expires_in * 1sec)

  assert ($now >= $expires_at2) "session should be expired"

  rm -rf test-sessions
  print "ok session-expiry"
}

# Provider session TTL is enforced by get-auth (distinct from the state TTL,
# which is our policy). A session past token_issued_at + expires_in with no
# usable refresh_token must be rejected AND evicted.
def test-session-expiry-enforced [] {
  let sandbox = mktemp -d
  let store = make-file-store ($sandbox | path join "sessions")

  # Issued 2h ago, expires_in 1h -> expired; no refresh_token to recover.
  let expired = {
    access_token: "test"
    expires_in: 3600
    token_issued_at: ((date now) - 2hr)
    user: {id: "1"}
    provider: "discord"
  }
  let hash = $expired | to json -r | do $store.set
  let req = {headers: {cookie: $"session=($hash)"}}

  let auth = get-auth {sessions: $store} $req (providers all)
  assert ($auth == null) "expired session without refresh_token must return null"
  assert ((do $store.get $hash) == null) "expired session must be evicted from the store"

  rm -rf $sandbox
  print "ok session-expiry-enforced"
}

# ============================================================================
# State expiry (HIGH): advertised 5-minute TTL + single use must be enforced,
# and the states dir must not grow without bound.
# ============================================================================

def fmt-ts [dt: datetime] {
  $dt | format date "%Y-%m-%dT%H:%M:%S%.3fZ"
}

def test-validate-state [] {
  let fresh = {token: "tok-abc", return_to: "/", provider_name: "discord", created_at: (fmt-ts (date now))}

  # Matching token, within TTL -> returns the state.
  let ok = validate-state "tok-abc" [$fresh]
  assert ($ok != null) "fresh matching state must validate"
  assert ($ok.token == "tok-abc") "validated state must be returned"

  # Wrong token -> null.
  assert ((validate-state "tok-wrong" [$fresh]) == null) "token mismatch must fail"

  # Missing token -> null (no throw).
  assert ((validate-state null [$fresh]) == null) "null token must fail"

  # Expired (created 6 minutes ago) -> null even with the right token.
  let stale = {token: "tok-old", return_to: "/", provider_name: "discord", created_at: (fmt-ts ((date now) - 6min))}
  assert ((validate-state "tok-old" [$stale]) == null) "expired state must fail TTL"

  # TTL is our policy: STATE_TTL is the default, overridable per call.
  assert ($STATE_TTL == 5min) "STATE_TTL default is 5min"
  # A 2-minute-old state passes the default but fails a tighter --ttl.
  let twomin = {token: "t2", return_to: "/", provider_name: "discord", created_at: (fmt-ts ((date now) - 2min))}
  assert ((validate-state "t2" [$twomin]) != null) "2m state ok under default TTL"
  assert ((validate-state "t2" [$twomin] --ttl 1min) == null) "2m state fails under 1min TTL"

  print "ok validate-state"
}

def test-store-ttl [] {
  let sandbox = mktemp -d

  # TTL store: lazy expiry on get.
  let ttl_store = make-file-store ($sandbox | path join "states") --ttl 5min
  let k = '{"s": 1}' | do $ttl_store.set
  assert ((do $ttl_store.get $k) == '{"s": 1}') "fresh ttl entry must read back"

  # Age the file past the TTL -> get returns null and removes it.
  ^touch -d "2000-01-01" ($sandbox | path join "states" | path join $k)
  assert ((do $ttl_store.get $k) == null) "expired entry must read as null"
  assert (not (($sandbox | path join "states" | path join $k) | path exists)) "expired entry must be removed on get"

  # sweep() bounds the dir: age one entry, keep one fresh, sweep, only fresh survives.
  let old = '{"old": 1}' | do $ttl_store.set
  let new = '{"new": 1}' | do $ttl_store.set
  ^touch -d "2000-01-01" ($sandbox | path join "states" | path join $old)
  do $ttl_store.sweep
  assert ((do $ttl_store.get $old) == null) "swept entry must be gone"
  assert ((do $ttl_store.get $new) == '{"new": 1}') "fresh entry must survive sweep"

  # No-ttl store never expires and sweep() is a no-op.
  let sess_store = make-file-store ($sandbox | path join "sessions")
  let sk = '{"long": "lived"}' | do $sess_store.set
  ^touch -d "2000-01-01" ($sandbox | path join "sessions" | path join $sk)
  do $sess_store.sweep
  assert ((do $sess_store.get $sk) == '{"long": "lived"}') "no-ttl entry must never expire"

  rm -rf $sandbox
  print "ok store-ttl"
}

# ============================================================================
# Open redirect (MEDIUM): the post-login Location must stay same-origin.
# ============================================================================

def test-safe-return-to [] {
  # Allowed: plain absolute paths (optionally with query/fragment).
  assert ((safe-return-to "/") == "/") "root path allowed"
  assert ((safe-return-to "/dashboard") == "/dashboard") "abs path allowed"
  assert ((safe-return-to "/a/b?x=1#y") == "/a/b?x=1#y") "abs path w/ query allowed"

  # Rejected -> "/": absolute URLs and protocol-relative tricks.
  for bad in ["//evil.com" '/\evil.com' "https://evil.com" "http://evil.com" "evil.com" "" null] {
    assert ((safe-return-to $bad) == "/") $"open-redirect vector must fall back to /: ($bad)"
  }

  print "ok safe-return-to"
}

# ============================================================================
# Allowlist footgun: authorization must key on immutable provider IDs, never
# usernames/emails; Google requires a verified email.
# ============================================================================

def test-allowlist [] {
  # Discord keys on the immutable snowflake id.
  let discord_user = {id: "111", username: "admin", email: "a@b.com"}
  assert ((account-id "discord" $discord_user) == "111") "discord id is the account id"
  assert (is-allowed "discord" $discord_user ["111"]) "allowlisted discord id passes"
  assert (not (is-allowed "discord" $discord_user ["999"])) "non-allowlisted id fails"
  # A username/email that happens to be on the list must NOT grant access.
  assert (not (is-allowed "discord" $discord_user ["admin"])) "username must not authorize"
  assert (not (is-allowed "discord" $discord_user ["a@b.com"])) "email must not authorize"

  # Google keys on sub, and only when email_verified is true.
  let g_ok = {sub: "sub-1", email: "x@y.com", email_verified: true}
  assert ((account-id "google" $g_ok) == "sub-1") "google sub is the account id"
  assert (is-allowed "google" $g_ok ["sub-1"]) "verified google sub passes"

  let g_unverified = {sub: "sub-1", email: "x@y.com", email_verified: false}
  assert ((account-id "google" $g_unverified) == null) "unverified google -> no id"
  assert (not (is-allowed "google" $g_unverified ["sub-1"])) "unverified google must fail"

  # Unknown provider -> no id, never allowed.
  assert ((account-id "acme" {id: "1"}) == null) "unknown provider -> null"

  print "ok allowlist"
}

# ============================================================================
# JWT trust footgun: decode-jwt must refuse an unsigned (alg=none) token.
# ============================================================================

def test-jwt-alg-none [] {
  let provider = providers all | get google

  # A well-formed but UNSIGNED token: header alg=none, forged admin claims.
  let header = '{"alg":"none","typ":"JWT"}' | encode base64 --url --nopad
  let payload = '{"iss":"https://accounts.google.com","sub":"attacker","email_verified":true}' | encode base64 --url --nopad
  let forged = $"($header).($payload)."

  let threw = try {
    do $provider.get-user $forged
    false
  } catch {
    true
  }
  assert $threw "get-user must reject an alg=none (unsigned) token"

  print "ok jwt-alg-none"
}

# ============================================================================
# Logout CSRF (MEDIUM): state-changing logout must require a valid per-session
# token, so a cross-site GET can't force-logout the victim.
# ============================================================================

def test-logout-csrf [] {
  let session = {user: {id: "1"}, csrf_token: "secret-token"}

  # Correct token -> authorized.
  assert (logout-authorized $session "secret-token") "matching csrf must authorize"

  # Wrong / missing token -> rejected.
  assert (not (logout-authorized $session "wrong")) "wrong csrf must be rejected"
  assert (not (logout-authorized $session null)) "missing csrf must be rejected"
  assert (not (logout-authorized $session "")) "empty csrf must be rejected"

  # No active session -> idempotent clear is allowed.
  assert (logout-authorized null "anything") "no session -> allowed"

  # Legacy session without a token -> best-effort allow (can't verify).
  assert (logout-authorized {user: {id: "1"}} null) "legacy session -> allowed"

  print "ok logout-csrf"
}

# ============================================================================
# Security regression tests: file-store path traversal (CRITICAL)
#
# The store key is taken verbatim from an attacker-controlled cookie
# (url-decoded by parse-cookies). If the store uses it directly as a filename,
# a "../" key escapes the store directory. Keys are SHA256 hex, so every key
# MUST match ^[a-f0-9]{64}$ at the get/update/delete boundary.
# ============================================================================

# The store boundary must reject any key that is not 64 lowercase hex chars.
def test-store-key-validation [] {
  let sandbox = mktemp -d
  let store = make-file-store ($sandbox | path join "store")

  # A real (valid) key round-trips.
  let good = '{"ok": true}' | do $store.set
  assert ($good =~ '^[a-f0-9]{64}$') "set must mint a 64-char hex key"
  assert ((do $store.get $good) == '{"ok": true}') "valid key must read back"

  # Plant a victim file OUTSIDE the store directory.
  let victim = $sandbox | path join "victim.txt"
  "top-secret" | save -f $victim

  # Traversal keys must be rejected everywhere the key is used.
  let bad_keys = [
    "../victim.txt"
    "..%2fvictim.txt"     # (what an encoded cookie looks like after decode is ../)
    "/etc/passwd"
    "abc"                 # too short
    ($good | str upcase)  # wrong case
    $"($good).json"       # extra suffix
  ]

  for k in $bad_keys {
    # get: never read outside the store
    assert ((do $store.get $k) == null) $"get must reject bad key: ($k)"
    # update: never write outside the store
    "pwned" | do $store.update $k
    # delete: never unlink outside the store
    do $store.delete $k
  }

  assert ($victim | path exists) "victim file must survive get/update/delete"
  assert ((open $victim) == "top-secret") "victim file must be unmodified"

  rm -rf $sandbox
  print "ok store-key-validation"
}

# EXPLOIT 1 (proven): unauth arbitrary file DELETE.
# handle-logout does `do $client.sessions.delete $session_hash` with the raw
# cookie value. A cookie of session=../<path> unlinks an arbitrary file.
# Regression at the exact boundary handle-logout calls.
def test-traversal-delete [] {
  let sandbox = mktemp -d
  let store = make-file-store ($sandbox | path join "sessions")

  let victim = $sandbox | path join "important.db"
  "do-not-delete" | save -f $victim

  # This is the value handle-logout passes straight to sessions.delete.
  do $store.delete "../important.db"

  assert ($victim | path exists) "arbitrary DELETE via traversal must be blocked"
  rm -rf $sandbox
  print "ok traversal-delete"
}

# EXPLOIT 2 (proven): arbitrary file READ -> auth bypass.
# A session cookie pointing at any JSON file with {"user":{"id":"<allowlisted>"}}
# and no expires_in makes get-auth return it as a valid session.
def test-traversal-auth-bypass [] {
  let sandbox = mktemp -d
  let store = make-file-store ($sandbox | path join "sessions")

  # Attacker-controlled / pre-existing file containing JSON somewhere on disk.
  # (No .json extension so `open` yields a raw string, exactly as a real
  # sha256-named session file would.)
  let forged = $sandbox | path join "forged"
  {user: {id: "9999-allowlisted-admin"}, provider: "discord"} | to json -r | save -f $forged

  # Cookie url-decodes to ../forged (see parse-cookies).
  let req = {headers: {cookie: "session=..%2fforged"}}
  let client = {sessions: $store}

  let auth = get-auth $client $req (providers all)
  assert ($auth == null) "traversal auth bypass must be blocked (get-auth returns null)"

  rm -rf $sandbox
  print "ok traversal-auth-bypass"
}

# ============================================================================
# Storage interface: run the SAME table-driven contract suite against BOTH the
# file impl and the xs impl. The xs store commands (.append/.last/.cas/...) are
# only available under http-nu, so the suite runs via `http-nu eval --store`.
# See test-contract.nu.
# ============================================================================

def test-store-contract [] {
  let store_dir = mktemp -d
  let result = (^http-nu eval --store $store_dir test-contract.nu | complete)
  rm -rf $store_dir

  # Surface the suite's ok/PRINT lines and any error.
  if ($result.stdout | is-not-empty) { print ($result.stdout | str trim) }
  if $result.exit_code != 0 {
    print ($result.stderr)
    error make {msg: "store contract suite (file + xs) failed"}
  }
  print "ok store-contract"
}

def assert [condition: bool, message: string] {
  if not $condition {
    error make {msg: $"Assertion failed: ($message)"}
  }
}
