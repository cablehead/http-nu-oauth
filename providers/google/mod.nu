# Google OAuth Provider
# Implements Google OAuth 2.0 flow with JWT support

# Decode Google JWT ID token
def decode-jwt []: string -> record {
  let $token = $in
  let parts = $token | split row "."

  # JWT uses base64url encoding without padding
  {
    h: ($parts.0 | decode base64 --url --nopad | decode)
    p: ($parts.1 | decode base64 --url --nopad | decode | from json)
    sig: $parts.2
  }
}

export def provider [] {
  {
    # Build Google authorization URL
    auth-url: {|client: record state: string|
      let auth_url = {
        scheme: "https"
        host: "accounts.google.com"
        path: "/o/oauth2/v2/auth"
        params: {
          client_id: $client.id
          redirect_uri: $client.redirect
          response_type: "code"
          scope: ($client.scopes | str join " ")
          state: $state
        }
      } | url join
      $auth_url
    }

    # Exchange authorization code for access token
    token-exchange: {|client: record code: string|
      let token_url = "https://oauth2.googleapis.com/token"
      let params = {
        client_id: $client.id
        client_secret: $client.secret
        code: $code
        redirect_uri: $client.redirect
        grant_type: "authorization_code"
      }

      http post --full --allow-errors $token_url --content-type "application/x-www-form-urlencoded" $params
    }

    # Get user info from Google (decode JWT id_token)
    get-user: {|access_token: string|
      # For Google, we decode the JWT to get user info
      let decoded = $access_token | decode-jwt | get p
      {
        status: 200
        body: $decoded
      }
    }

    # Optional: Verify token with Google's tokeninfo endpoint
    verify-token: {|id_token: string|
      let url = {
        scheme: "https"
        host: "oauth2.googleapis.com"
        path: "tokeninfo"
        params: {
          id_token: $id_token
        }
      } | url join
      http get --full --allow-errors $url
    }

    # Refresh access token using refresh token
    token-refresh: {|client: record refresh_token: string|
      let token_url = "https://oauth2.googleapis.com/token"
      let params = {
        client_id: $client.id
        client_secret: $client.secret
        grant_type: "refresh_token"
        refresh_token: $refresh_token
      }

      http post --full --allow-errors $token_url --content-type "application/x-www-form-urlencoded" $params
    }
  }
}
