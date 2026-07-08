# OAuth Common Library
# Provides shared functionality for OAuth 2.0 flows across providers

use ./providers

# Helper: Optional chaining
def and-then [next: closure --else: closure] {
  if ($in | is-not-empty) { do $next } else {
    if $else != null { do $else }
  }
}

# ============================================================================
# CSRF Challenge Management
#
# A "challenge" is a short-lived, single-use record we create before redirecting
# to the provider and verify when the provider redirects back. Its token rides
# the OAuth `state` query parameter out and back — so "challenge" is our
# app-side concept, "state" is only the wire parameter that carries the token.
# ============================================================================

# Generate a random challenge token using UUIDv4.
export def generate-challenge [return_to: string, provider_name: string] {
  let token = random uuid
  let challenge_data = {
    token: $token
    return_to: $return_to
    provider_name: $provider_name
    created_at: (date now | format date "%Y-%m-%dT%H:%M:%S%.3fZ")
  }
  {
    token: $token
    data: $challenge_data
  }
}

# Clamp a post-login redirect target to a same-origin path, defeating open
# redirects. Only a plain absolute path ("/...") is allowed; anything else
# (absolute URL, protocol-relative "//host" or "/\host", or a non-string)
# falls back to "/".
export def safe-return-to [return_to: any] {
  if ($return_to | describe) != "string" { return "/" }
  if not ($return_to | str starts-with "/") { return "/" }
  if ($return_to | str starts-with "//") { return "/" }
  if ($return_to | str starts-with '/\') { return "/" }
  $return_to
}

# Lifetime of a CSRF challenge. We (the relying party) mint the challenge, so
# its lifetime is our policy: there is nothing authoritative in the token to
# derive it from. This is distinct from session lifetime, which is driven by the
# provider's `expires_in` (see get-auth). Override per-call via `--ttl`.
export const CHALLENGE_TTL = 5min

# Validate a presented token against the stored challenges.
# The token is `any` because it comes straight from the OAuth `state` query
# param and may be null (missing); a null/mismatched token simply fails to match.
export def validate-challenge [token: any, stored_challenges: list, --ttl: duration] {
  let limit = ($ttl | default $CHALLENGE_TTL)

  if ($token | is-empty) {
    return null
  }

  let match = $stored_challenges | where token == $token | first

  if ($match | is-empty) {
    return null
  }

  # Reject challenges older than the policy TTL.
  let created = $match.created_at | into datetime
  let now = date now

  if ($now - $created) > $limit {
    return null
  }

  $match
}

# ============================================================================
# Cookie Management
# ============================================================================

# Parse cookie header into record
export def parse-cookies [] {
  $in | and-then {
    split row ";" | each {
      str trim | split row "=" -n 2 | [$in.0 ($in.1 | url decode)]
    } | into record
  }
}

# Create session cookie
export def set-cookie [
  redirect_uri: string
  name: string
  value: string
] {
  let parsed = ($redirect_uri | url parse)
  let cookie_value = {$name: $value} | url build-query

  if $parsed.scheme == "http" {
    $"($cookie_value); Path=/; HttpOnly; SameSite=Lax"
  } else {
    $"($cookie_value); Path=/; HttpOnly; Secure; SameSite=Lax"
  }
}

# Clear cookie
export def clear-cookie [
  redirect_uri: string
  name: string
] {
  let parsed = ($redirect_uri | url parse)
  if $parsed.scheme == "http" {
    $"($name)=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
  } else {
    $"($name)=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
  }
}

# ============================================================================
# Storage interface
# ============================================================================
#
# A store is a record of closures. It is a key/value store where the key is
# minted by the store (not chosen by the caller) and the value is an opaque
# UTF-8 string (callers store JSON).
#
#   set:    {|| -> string }          # pipe value in; returns a fresh KEY
#   get:    {|key: string| -> any }  # returns the stored value, or null
#   update: {|key: string| }         # pipe value in; overwrites value at KEY
#   delete: {|key: string| }         # removes KEY
#   sweep:  {|| }                    # GC expired entries (no-op without ttl)
#
# Contract:
#   - KEY FORMAT: keys are opaque tokens minted by `set`. Every implementation
#     here mints a 64-char lowercase-hex key (see valid-store-key). Callers MUST
#     treat keys as opaque and MUST NOT construct their own.
#   - KEY VALIDATION (load-bearing): keys reach the store straight from an
#     attacker-controlled cookie. Implementations MUST validate the key shape at
#     the get/update/delete boundary and treat any malformed key as absent —
#     never letting it escape the store's namespace (no path traversal, no topic
#     injection).
#   - RETURN TYPES: get returns the stored string, or null when the key is
#     absent, malformed, or expired. set returns the new key (string). update
#     and delete return nothing.
#   - ERROR BEHAVIOR: get/update/delete on an absent or malformed key never
#     throw; get yields null, update/delete are no-ops.
#   - TTL: a store MAY be created with a TTL for ephemeral entries (CSRF
#     challenges). Entries past their TTL read as null; how they are reclaimed
#     is the implementation's concern (file: mtime sweep; xs: native frame TTL).
#
# Two implementations follow: make-file-store (file-backed) and make-xs-store
# (cross.stream-backed). Both satisfy this contract and are exercised by the
# same table-driven suite in test-contract.nu. Both take an optional --ttl
# (a nushell duration): omit it for a PERSISTENT store (sessions), pass it for
# an EXPIRING store (challenges).

# Store keys are 64-char lowercase-hex tokens (a SHA256 digest for the file
# store, random bytes for the xs store). Validating this shape at the boundary
# is what stops a "../" cookie value from escaping the store's namespace (path
# traversal / topic injection). Any key that isn't exactly 64 hex chars is
# rejected.
export def valid-store-key [] {
  let key = $in
  ($key | describe) == "string" and ($key =~ '^[a-f0-9]{64}$')
}

# Remove every file under $path whose mtime is older than $ttl. Used to bound
# disk for an expiring store (challenges) so an attacker cannot flood it.
def sweep-expired [path: string, ttl: duration] {
  let now = date now
  ls $path | where type == file | where { |r| ($now - $r.modified) > $ttl } | each { |r|
    rm -f $r.name
  }
  null
}

# Create a file-based key-value store.
#
# Persistent by default. Pass --ttl to make it EXPIRING: reads lazily expire
# stale files and every write sweeps expired files, so the directory stays
# bounded (sessions omit --ttl; challenges pass one).
export def make-file-store [path: string, --ttl: duration] {
  mkdir $path
  {
    set: {||
      let content = $in
      let hash = $content | hash sha256
      $content | save -r -f ($path | path join $hash)
      if $ttl != null { sweep-expired $path $ttl }
      $hash
    }

    get: {|hash|
      if not ($hash | valid-store-key) { return null }
      let file = $path | path join $hash
      if not ($file | path exists) { return null }
      if $ttl != null {
        let age = (date now) - (ls $file | get 0.modified)
        if $age > $ttl {
          rm -f $file
          return null
        }
      }
      open -r $file
    }

    update: {|hash|
      let content = $in
      if not ($hash | valid-store-key) { return }
      let file = $path | path join $hash
      if ($file | path exists) { $content | save -r -f $file }
    }

    delete: {|hash|
      if not ($hash | valid-store-key) { return }
      let file = $path | path join $hash
      if ($file | path exists) { rm $file }
    }

    # Proactively remove expired entries (no-op when the store has no ttl).
    sweep: {||
      if $ttl != null { sweep-expired $path $ttl }
    }
  }
}

# Mint a fresh opaque store key: 64 lowercase-hex chars (two random UUIDs with
# their dashes stripped). Matches valid-store-key.
def new-store-key [] {
  [(random uuid) (random uuid)] | str join | str replace --all "-" ""
}

# Create a cross.stream (xs) key-value store.
#
# Requires the xs store commands (.append/.last/.cas/.cat/.remove), i.e. run
# under `http-nu --store <dir>` (or `http-nu eval --store <dir>` in tests).
#
# Each logical entry is its own topic `<base>.<key>`, and the entry's value is
# that topic's most recent frame (content lives in CAS, referenced by the
# frame's hash). This gives a mutable cell with a stable key. --ttl (a nushell
# duration, same as the file store) selects the frame retention:
#   - PERSISTENT (no --ttl): append with `last:1`, so only the current value is
#     retained (superseded versions are pruned by the store), kept indefinitely.
#   - EXPIRING (--ttl): append with a native frame ttl (`time:<ms>`), so entries
#     (challenges) expire on their own, no manual sweep.
# `base` must be a valid topic segment (e.g. "session", "challenge").
export def make-xs-store [base: string, --ttl: duration] {
  # Translate the duration to xs's native frame-ttl form; persistent stores keep
  # only the latest value per key.
  let retention = if $ttl == null {
    "last:1"
  } else {
    $"time:($ttl / 1ms | into int)"
  }
  {
    set: {||
      let content = $in
      let key = new-store-key
      $content | .append $"($base).($key)" --ttl $retention | ignore
      $key
    }

    get: {|key|
      if not ($key | valid-store-key) { return null }
      let frame = .last $"($base).($key)"
      if ($frame | is-empty) { return null }
      .cas $frame.hash
    }

    update: {|key|
      let content = $in
      if not ($key | valid-store-key) { return }
      $content | .append $"($base).($key)" --ttl $retention | ignore
    }

    delete: {|key|
      if not ($key | valid-store-key) { return }
      .cat --topic $"($base).($key)" | each {|frame| .remove $frame.id } | ignore
    }

    # Ephemeral entries expire via native frame ttl; nothing to sweep.
    sweep: {|| }
  }
}

# ============================================================================
# Authorization / allowlist
#
# A hard allowlist gates destructive actions, so it MUST key on an immutable,
# provider-issued account identifier — never a username or email. Usernames and
# email addresses can be changed, and (for some providers) reassigned to a
# different person after an account is deleted, which would silently grant a
# stranger admin rights.
#   - Discord: `user.id` (snowflake) is immutable.
#   - Google:  `user.sub` (subject) is immutable and stable per app; only trust
#              it when `email_verified` is true.
# ============================================================================

# Extract the stable identifier to allowlist against, or null if none can be
# trusted for this provider/user.
export def account-id [provider: string, user: record] {
  match $provider {
    "discord" => ($user.id? | default null)
    "google" => {
      # Google may send email_verified as a bool or the string "true".
      let verified = ($user.email_verified? in [true "true"])
      if $verified { $user.sub? | default null } else { null }
    }
    _ => null
  }
}

# Is this authenticated user on the allowlist of immutable IDs? The allowlist
# holds provider-issued IDs (Discord snowflakes / Google subs), never
# usernames or emails.
export def is-allowed [provider: string, user: record, allowlist: list] {
  let id = account-id $provider $user
  ($id | is-not-empty) and ($id in $allowlist)
}

# ============================================================================
# OAuth Flow Handlers
# ============================================================================

# Get authenticated user from session
export def get-auth [client req providers: record] {
  let cookies = $req.headers | get cookie? | parse-cookies
  let session_hash = $cookies | get session?
  let session = $session_hash | and-then {
    do $client.sessions.get $in | and-then {
      from json
    }
  }

  # Check if token is expired
  if ($session | is-not-empty) {
    let expires_in = $session.expires_in?
    if ($expires_in | is-not-empty) {
      let issued_at = $session.token_issued_at | into datetime
      let expires_at = $issued_at + ($expires_in * 1sec)
      let now = date now
      if $now >= $expires_at {
        # Try to refresh token
        let refresh_token = $session.refresh_token?
        if ($refresh_token | is-not-empty) {
          let provider = $providers | get ($session.provider)
          let token_refresh = $provider.token-refresh?
          if ($token_refresh | is-not-empty) {
            let token_resp = do $token_refresh $client $refresh_token
            if $token_resp.status < 399 {
              # Update session with refreshed token. Carry forward fields the
              # refresh response omits: the csrf_token (logout gate) and, when
              # the provider didn't reissue one, the refresh_token itself.
              let updated_session = $token_resp.body
              | insert token_issued_at (date now)
              | insert user $session.user
              | insert provider $session.provider
              | insert csrf_token ($session.csrf_token? | default (random uuid))
              | upsert refresh_token ($token_resp.body.refresh_token? | default $refresh_token)
              $updated_session | to json -r | do $client.sessions.update $session_hash
              return $updated_session
            }
          }
        }
        # Token expired and couldn't refresh - delete session
        do $client.sessions.delete $session_hash
        return null
      }
    }
  }

  $session
}

# Build authorization URL. `state` is the OAuth wire parameter value (the
# challenge token) the provider echoes back on callback.
export def get-auth-url [
  provider: record
  client: record
  state: string
] {
  do $provider.auth-url $client $state
}

# Initiate OAuth flow (redirect to provider)
export def handle-oauth [
  provider: record
  client: record
  return_to: string
] {
  # Mint a CSRF challenge and store it under an opaque key.
  let challenge = generate-challenge $return_to $client.provider_name
  let challenge_key = $challenge.data | to json -r | do $client.challenges.set

  # The challenge token travels out as the OAuth `state` parameter.
  let auth_url = get-auth-url $provider $client $challenge.token

  .response {
    status: 302
    headers: {
      Location: $auth_url
      "Set-Cookie": (set-cookie $client.redirect "oauth_challenge" $challenge_key)
    }
  }
}

# Handle OAuth callback
export def handle-oauth-callback [
  provider: record
  client: record
  req: record
] {
  # Verify the CSRF challenge.
  let cookies = $req.headers | get cookie? | parse-cookies
  let challenge_key = $cookies | get -o oauth_challenge

  if ($challenge_key | is-empty) {
    .response {status: 400}
    return "Error: Missing challenge cookie"
  }

  let stored_raw = do $client.challenges.get $challenge_key
  if ($stored_raw | is-empty) {
    # Unknown, expired (TTL swept), or already-used challenge.
    .response {status: 400}
    return "Error: Invalid or expired challenge"
  }

  let stored_challenge = $stored_raw | from json
  # The token the provider echoed back via the OAuth `state` parameter.
  let presented_token = $req.query | get -o state

  # Validate token match + TTL (single use is enforced by the delete below,
  # which runs whether or not validation passes).
  let valid = validate-challenge $presented_token [$stored_challenge]

  # Consume the challenge before deciding: one-time use, and an expired
  # challenge must not linger.
  do $client.challenges.delete $challenge_key

  if ($valid | is-empty) {
    .response {status: 400}
    return "Error: Invalid or expired challenge (CSRF check failed)"
  }

  # Validate code
  if ($req.query | get -o code | is-empty) {
    .response {status: 400}
    return "Error: No auth code provided"
  }

  # Exchange code for token
  let token_resp = do $provider.token-exchange $client $req.query.code

  if $token_resp.status >= 399 {
    .response {status: 400}
    return $"Error: Failed to get token (($token_resp.status))"
  }

  # Get user info
  # For Google, pass id_token if available (for JWT decoding), otherwise access_token
  let user_token = $token_resp.body.id_token? | default $token_resp.body.access_token
  let user_resp = do $provider.get-user $user_token

  if $user_resp.status >= 399 {
    .response {status: 400}
    return "Error: Failed to fetch user info"
  }

  # Store session. csrf_token gates state-changing actions like logout.
  let session_data = $token_resp.body
  | insert token_issued_at (date now)
  | insert user $user_resp.body
  | insert provider $stored_challenge.provider_name
  | insert csrf_token (random uuid)

  let session_hash = $session_data | to json -r | do $client.sessions.set

  # Set session cookie and clear the challenge cookie.
  let set_session = set-cookie $client.redirect "session" $session_hash
  let clear_challenge = clear-cookie $client.redirect "oauth_challenge"

  .response {
    status: 302
    headers: {
      Location: (safe-return-to $stored_challenge.return_to)
      "Set-Cookie": [$set_session $clear_challenge]
    }
  }
}

# Decide whether a logout request is authorized (CSRF check). Logout is
# state-changing, so it must carry a token that only the real session holder
# can know. We use a per-session synchronizer token minted at login:
#   - no active session: nothing to protect, allow (idempotent cookie clear).
#   - session predates this token (legacy): can't verify, allow (best effort).
#   - otherwise: the presented token must equal the session's csrf_token.
export def logout-authorized [session: any, provided_csrf: any] {
  if ($session | is-empty) { return true }
  let expected = $session.csrf_token?
  if ($expected | is-empty) { return true }
  ($provided_csrf | is-not-empty) and ($provided_csrf == $expected)
}

# Handle logout
export def handle-logout [client: record, req: record] {
  let cookies = $req.headers | get cookie? | parse-cookies
  let session_hash = $cookies | get -o session

  let session = $session_hash | and-then {
    do $client.sessions.get $in | and-then { from json }
  }
  let provided_csrf = $req | get -o query | default {} | get -o csrf

  # Reject state-changing GET without a valid CSRF token.
  if not (logout-authorized $session $provided_csrf) {
    .response {status: 403}
    return "Error: Invalid CSRF token"
  }

  if ($session_hash | is-not-empty) {
    do $client.sessions.delete $session_hash
  }

  # Clear both session and challenge cookies (list syntax = multiple Set-Cookie).
  let clear_session = clear-cookie $client.redirect "session"
  let clear_challenge = clear-cookie $client.redirect "oauth_challenge"

  .response {
    status: 302
    headers: {
      Location: "/"
      "Set-Cookie": [$clear_session $clear_challenge]
    }
  }
}
