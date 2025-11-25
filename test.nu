#!/usr/bin/env nu
# OAuth Library Tests
# Run with: nu test.nu

use lib.nu *
use providers

def main [] {
  print "Running tests...\n"

  test-exports
  test-store
  test-google-jwt
  test-session-expiry

  print "\n✓ All tests passed"
}

def test-exports [] {
  print "Testing exports..."

  # lib.nu exports
  let _ = (make-simplefile-store "test-tmp" | describe)
  let _ = (generate-state "/" "test" | describe)
  let _ = (parse-cookies | describe)

  # providers
  let all_providers = providers all
  assert ($all_providers | get google? | is-not-empty) "google provider missing"
  assert ($all_providers | get discord? | is-not-empty) "discord provider missing"

  rm -rf test-tmp
  print "  ✓ exports"
}

def test-store [] {
  print "Testing store..."

  let store = make-simplefile-store "test-store"

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
  print "  ✓ store"
}

def test-google-jwt [] {
  print "Testing Google JWT decoding..."

  let fixture = open fixtures/google/token-response.json
  let provider = providers all | get google

  # get-user decodes the JWT
  let user_resp = do $provider.get-user $fixture.id_token

  assert ($user_resp.status == 200) "status should be 200"
  assert ($user_resp.body.email == "test@example.com") "email should match"
  assert ($user_resp.body.iss == "https://accounts.google.com") "issuer should match"

  print "  ✓ google jwt"
}

def test-session-expiry [] {
  print "Testing session expiry..."

  let store = make-simplefile-store "test-sessions"

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
  print "  ✓ session expiry"
}

def assert [condition: bool, message: string] {
  if not $condition {
    error make {msg: $"Assertion failed: ($message)"}
  }
}
