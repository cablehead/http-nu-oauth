use ../../lib.nu oauth
use ../../providers

def load-client [] {
  let sessions_dir = (pwd | collect | path join "sessions")
  mkdir $sessions_dir

  let states_dir = (pwd | collect | path join "states")
  mkdir $states_dir

  {
    provider_name: "google"
    id: $env.GOOGLE_CLIENT_ID
    secret: $env.GOOGLE_CLIENT_SECRET
    redirect: $env.GOOGLE_REDIRECT_URI
    scopes: ($env.GOOGLE_SCOPES | split row " ")
    sessions: (oauth make-session-store $sessions_dir)
    states: (oauth make-session-store $states_dir)
  }
}

{|req|
  let client = load-client
  let provider = providers all | get google

  match $req {
    {method: "GET", path: "/auth/logout"} => {
      return (oauth handle-logout $client)
    }

    {method: "GET", path: "/auth/callback"} => {
      return (oauth handle-oauth-callback $provider $client $req)
    }
  }

  let auth = (oauth get-auth $client $req)
  if ($auth | is-empty) {
    return (oauth handle-oauth $provider $client "/")
  }

  # Display Google user info
  $"<html>
  <head><title>Google OAuth Example</title></head>
  <body style='font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;'>
    <h1>Hello, ($auth.user.name)!</h1>
    <p><strong>Email:</strong> ($auth.user.email)</p>
    <p><strong>User ID:</strong> ($auth.user.sub)</p>
    <p><strong>Provider:</strong> ($auth.provider)</p>
    <p><a href='/auth/logout'>Logout</a></p>
    <hr>
    <p><em>Secured with CSRF-protected OAuth 2.0</em></p>
  </body>
  </html>"
}
