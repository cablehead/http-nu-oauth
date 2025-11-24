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
# CSRF State Management
# ============================================================================

# Generate random state token using UUIDv4
export def generate-state [return_to: string, provider_name: string] {
  let token = random uuid
  let state_data = {
    token: $token
    return_to: $return_to
    provider_name: $provider_name
    created_at: (date now | format date "%Y-%m-%dT%H:%M:%S%.3fZ")
  }
  {
    token: $token
    data: $state_data
  }
}

# Validate state token matches stored state
export def validate-state [state_token: string, stored_states: list] {
  let match = $stored_states | where token == $state_token | first

  if ($match | is-empty) {
    return null
  }

  # Check if state is expired (5 minutes)
  let created = $match.created_at | into datetime
  let now = date now
  let age = ($now - $created) | into int

  if $age > 300_000_000_000 {  # 5 minutes in nanoseconds
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
# Session Storage
# ============================================================================

# Helper to get storage path - called from within closures
def get-storage-path [base_dir: string, hash: string] {
  $base_dir | path join $hash
}

# Create session store with filesystem backend
export def make-session-store [sessions_dir: string] {
  return {
    set: {||
      let content = $in
      let hash = $content | hash sha256
      let path = get-storage-path $sessions_dir $hash
      $content | save -f $path
      $hash
    }

    get: {|hash|
      let path = get-storage-path $sessions_dir $hash
      if ($path | path exists) {
        open $path
      }
    }

    update: {|hash|
      let content = $in
      let path = get-storage-path $sessions_dir $hash
      if ($path | path exists) {
        $content | save -f $path
      }
    }

    delete: {|hash|
      let path = get-storage-path $sessions_dir $hash
      if ($path | path exists) {
        rm $path
      }
    }
  }
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
              # Update session with refreshed token
              let updated_session = $token_resp.body
                | insert token_issued_at (date now | format date "%Y-%m-%dT%H:%M:%S%.3fZ")
                | insert user $session.user
                | insert provider $session.provider
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

# Build authorization URL
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
  # Generate CSRF state
  let state_info = generate-state $return_to $client.provider_name
  let state_hash = $state_info.data | to json -r | do $client.states.set

  # Build auth URL with state token
  let auth_url = get-auth-url $provider $client $state_info.token

  .response {
    status: 302
    headers: {
      Location: $auth_url
      "Set-Cookie": (set-cookie $client.redirect "oauth_state" $state_hash)
    }
  }
}

# Handle OAuth callback
export def handle-oauth-callback [
  provider: record
  client: record
  req: record
] {
  # Validate state (CSRF protection)
  let cookies = $req.headers | get cookie? | parse-cookies
  let state_hash = $cookies | get -i oauth_state

  if ($state_hash | is-empty) {
    .response {status: 400}
    return "Error: Missing state cookie"
  }

  let stored_state = do $client.states.get $state_hash | from json
  let state_token = $req.query | get -i state

  if $state_token != $stored_state.token {
    .response {status: 400}
    return "Error: Invalid state (CSRF check failed)"
  }

  # Delete used state (one-time use)
  do $client.states.delete $state_hash

  # Validate code
  if ($req.query | get -i code | is-empty) {
    .response {status: 400}
    return "Error: No auth code provided"
  }

  # Exchange code for token
  let token_resp = do $provider.token-exchange $client $req.query.code

  # Debug: save token response
  $token_resp | to json | save -f /tmp/oauth-token-response.json

  if $token_resp.status >= 399 {
    .response {status: 400}
    return $"Error: Failed to get token (($token_resp.status))"
  }

  # Get user info
  # For Google, pass id_token if available (for JWT decoding), otherwise access_token
  let user_token = $token_resp.body.id_token? | default $token_resp.body.access_token

  # Debug: save user token
  $user_token | save -f /tmp/oauth-user-token.txt

  let user_resp = do $provider.get-user $user_token

  if $user_resp.status >= 399 {
    .response {status: 400}
    return "Error: Failed to fetch user info"
  }

  # Store session
  let session_data = $token_resp.body
    | insert token_issued_at (date now | format date "%Y-%m-%dT%H:%M:%S%.3fZ")
    | insert user $user_resp.body
    | insert provider $stored_state.provider_name

  # Debug: save session data before storing
  $"SESSION DATA: ($session_data | to json -r)\n" | save -a /tmp/session-debug.log

  let session_hash = $session_data | to json -r | do $client.sessions.set

  # Debug: log session hash
  $"SESSION HASH: ($session_hash)\n" | save -a /tmp/session-debug.log

  # Set session cookie and clear oauth_state cookie
  let set_session = set-cookie $client.redirect "session" $session_hash
  let clear_state = clear-cookie $client.redirect "oauth_state"

  .response {
    status: 302
    headers: {
      Location: $stored_state.return_to
      "Set-Cookie": [$set_session, $clear_state]
    }
  }
}

# Handle logout
export def handle-logout [client: record, req: record] {
  let cookies = $req.headers | get cookie? | parse-cookies
  let session_hash = $cookies | get -i session

  $"LOGOUT: session_hash = ($session_hash)\n" | save -a /tmp/session-debug.log

  if ($session_hash | is-not-empty) {
    $"LOGOUT: calling delete for ($session_hash)\n" | save -a /tmp/session-debug.log
    do $client.sessions.delete $session_hash
    $"LOGOUT: delete called\n" | save -a /tmp/session-debug.log
  }

  # Clear both session and state cookies using list syntax for multiple Set-Cookie headers
  let clear_session = clear-cookie $client.redirect "session"
  let clear_state = clear-cookie $client.redirect "oauth_state"

  .response {
    status: 302
    headers: {
      Location: "/"
      "Set-Cookie": [$clear_session, $clear_state]
    }
  }
}
