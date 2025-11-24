# Discord OAuth Provider
# Implements Discord OAuth 2.0 flow

export def provider [] {
  {
    # Build Discord authorization URL
    auth-url: {|client: record state: string|
      let auth_url = {
        scheme: "https"
        host: "discord.com"
        path: "/api/oauth2/authorize"
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
      let token_url = "https://discord.com/api/oauth2/token"
      let params = {
        client_id: $client.id
        client_secret: $client.secret
        code: $code
        redirect_uri: $client.redirect
        grant_type: "authorization_code"
      }

      http post --full --allow-errors $token_url --content-type "application/x-www-form-urlencoded" $params
    }

    # Get user info from Discord API
    get-user: {|access_token: string|
      let url = "https://discord.com/api/users/@me"
      http get --full --allow-errors --headers [Authorization $"Bearer ($access_token)"] $url
    }

    # Refresh access token using refresh token
    token-refresh: {|client: record refresh_token: string|
      let token_url = "https://discord.com/api/oauth2/token"
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
