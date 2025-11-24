use ../lib.nu *
use ../providers

def load-client [provider_name: string] {
  let config = $env.OAUTH_CONFIG | from json
  let provider_config = $config.providers | get $provider_name

  let sessions_dir = pwd | collect | path join "sessions"
  mkdir $sessions_dir

  let states_dir = pwd | collect | path join "states"
  mkdir $states_dir

  {
    provider_name: $provider_name
    id: $provider_config.client_id
    secret: $provider_config.client_secret
    redirect: $config.redirect_uri
    scopes: $provider_config.scopes
    sessions: (make-session-store $sessions_dir)
    states: (make-session-store $states_dir)
  }
}

def render-provider-list [] {
  let config = $env.OAUTH_CONFIG | from json
  let provider_names = $config.providers | columns

  let provider_links = $provider_names | each {|name|
    $"<li><a href='/auth/login/($name)'>Login with ($name)</a></li>"
  } | str join "\n"

  $"<html>
  <head><title>Multi-Provider OAuth</title></head>
  <body style='font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;'>
    <h1>Choose a provider to login</h1>
    <ul>
      ($provider_links)
    </ul>
  </body>
  </html>"
}

def render-user-info [auth: record] {
  let user = $auth.user
  let provider = $auth.provider

  # Calculate time until token expiry
  let expires_info = if ($auth.expires_in? | is-not-empty) {
    let issued_at = $auth.token_issued_at | into datetime
    let expires_at = $issued_at + ($auth.expires_in * 1sec)
    let now = date now
    let remaining = $expires_at - $now
    let remaining_secs = $remaining | into int | $in / 1_000_000_000
    let hours = ($remaining_secs / 3600) | into int
    let minutes = (($remaining_secs mod 3600) / 60) | into int
    let seconds = ($remaining_secs mod 60) | into int
    $"<p style='color: #666;'>Token expires in: ($hours)h ($minutes)m ($seconds)s</p>"
  } else {
    ""
  }

  let user_fields = $user | transpose key value | each {|row|
    $"<tr><td><strong>($row.key):</strong></td><td>($row.value)</td></tr>"
  } | str join "\n"

  $"<html>
  <head><title>Logged In</title></head>
  <body style='font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;'>
    <h1>Logged in with ($provider)</h1>
    ($expires_info)
    <h2>User Information</h2>
    <table style='border-collapse: collapse; width: 100%;'>
      ($user_fields)
    </table>
    <hr>
    <p><a href='/auth/logout'>Logout</a></p>
  </body>
  </html>"
}

{|req|
  match $req {
    {method: "GET", path: "/auth/logout"} => {
      let config = $env.OAUTH_CONFIG | from json
      let first_provider = $config.providers | columns | first
      let client = load-client $first_provider
      return (handle-logout $client $req)
    }

    {method: "GET", path: $path} if ($path | str starts-with "/auth/login/") => {
      let provider_name = $path | str replace "/auth/login/" ""
      let client = load-client $provider_name
      let provider = providers all | get $provider_name
      return (handle-oauth $provider $client "/")
    }

    {method: "GET", path: "/auth/callback"} => {
      # Get provider name from state cookie
      let cookies = $req.headers | get cookie? | parse-cookies
      let state_hash = $cookies | get -i oauth_state

      if ($state_hash | is-empty) {
        .response {status: 400}
        return "Error: Missing state cookie"
      }

      # Load state to get provider name
      let sessions_dir = pwd | collect | path join "sessions"
      let states_dir = pwd | collect | path join "states"
      let temp_client = {
        states: (make-session-store $states_dir)
      }

      let stored_state = do $temp_client.states.get $state_hash | from json
      let provider_name = $stored_state.provider_name

      # Now load proper client and provider
      let client = load-client $provider_name
      let provider = providers all | get $provider_name
      return (handle-oauth-callback $provider $client $req)
    }

    {method: "GET", path: "/"} => {
      let config = $env.OAUTH_CONFIG | from json
      let first_provider = $config.providers | columns | first
      let client = load-client $first_provider

      let auth = get-auth $client $req (providers all)
      if ($auth | is-empty) {
        return (render-provider-list)
      } else {
        return (render-user-info $auth)
      }
    }
  }
}
