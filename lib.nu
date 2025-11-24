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
# CSRF State Management (Security Fix)
# ============================================================================

# Generate cryptographically secure random state token
export def generate-state [return_to: string] {
  let token = random chars --length 32
  let state_data = {
    token: $token
    return_to: $return_to
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

# Create session store with filesystem backend
export def make-session-store [sessions_dir: string] {
  return {
    set: {||
      let content = $in
      let hash = $in | hash sha256
      let path = ($sessions_dir | path join $hash)
      $in | save $path
      $hash
    }

    get: {|hash|
      let path = ($sessions_dir | path join $hash)
      if ($path | path exists) {
        open $path
      }
    }

    delete: {|hash|
      let path = ($sessions_dir | path join $hash)
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
export def get-auth [client req] {
  let cookies = $req.headers | get cookie? | parse-cookies
  $cookies | and-then {
    get session? | and-then {
      do $client.sessions.get $in | and-then {
        from json
      }
    }
  }
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
  let state_info = generate-state $return_to
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

  if $token_resp.status >= 399 {
    .response {status: 400}
    return $"Error: Failed to get token (($token_resp.status))"
  }

  # Get user info
  let user_resp = do $provider.get-user $token_resp.body.access_token

  if $user_resp.status >= 399 {
    .response {status: 400}
    return "Error: Failed to fetch user info"
  }

  # Store session
  let session_data = {
    access_token: $token_resp.body.access_token
    user: $user_resp.body
    provider: $client.provider_name
  }
  let session_hash = $session_data | to json -r | do $client.sessions.set

  .response {
    status: 302
    headers: {
      Location: $stored_state.return_to
      "Set-Cookie": (set-cookie $client.redirect "session" $session_hash)
    }
  }
}

# Handle logout
export def handle-logout [client: record] {
  let cookies = $"" | get cookie? | parse-cookies  # Get from request
  let session_hash = $cookies | get -i session

  if ($session_hash | is-not-empty) {
    do $client.sessions.delete $session_hash
  }

  .response {
    status: 302
    headers: {
      Location: "/"
      "Set-Cookie": (clear-cookie $client.redirect "session")
    }
  }
}
