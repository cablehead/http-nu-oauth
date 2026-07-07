# Google OAuth Provider
# Implements Google OAuth 2.0 flow with JWT support

# Decode a Google JWT ID token.
#
# SECURITY: this decodes but does NOT verify the RS256 signature. It is only
# safe because get-user is fed the id_token straight from Google's token
# endpoint (fetched over TLS in token-exchange), which authenticates the token
# by transport. This function MUST NEVER be called on a token from an
# untrusted source (e.g. a user-supplied header/cookie): an attacker could
# forge arbitrary claims. To accept tokens from untrusted sources, verify the
# signature against Google's JWKS or call verify-token (tokeninfo) first.
#
# As defence-in-depth we still refuse the classic forgery — an unsigned
# ("alg":"none") token — and structurally malformed input.
def decode-jwt []: string -> record {
  let $token = $in
  let parts = $token | split row "."

  if ($parts | length) != 3 {
    error make {msg: "malformed JWT: expected 3 dot-separated segments"}
  }

  # JWT uses base64url encoding without padding
  let header = ($parts.0 | decode base64 --url --nopad | decode)
  let alg = ($header | from json | get alg? | default "" | str downcase)
  if $alg == "none" {
    error make {msg: "refusing to decode unsigned (alg=none) JWT"}
  }

  {
    h: $header
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

    # Get user info from Google by decoding the id_token JWT.
    # The argument MUST be an id_token obtained from token-exchange (Google's
    # token endpoint) — see decode-jwt's security note. Do not pass a token
    # from any untrusted source without verifying its signature first.
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
