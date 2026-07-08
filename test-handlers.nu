#!/usr/bin/env nu
# Handler response regression tests.
#
# The bug these guard: http-nu has no `.response` command. A handler's status
# and headers ride the returned value's `http.response` PIPELINE METADATA, which
# http-nu reads off the tail expression. That metadata does not survive `return`
# or `let`, so every handler must emit its response in tail position.
#
# These drive each handler with a synthetic request under the real http-nu
# runtime (run via `http-nu eval --store <dir>`, which also provides the xs
# store commands) and assert the metadata the served response would carry.

use lib.nu *
use providers

# Read the http.response metadata off a handler's return value. MUST receive the
# handler call as a pipeline; a `let`-bound value has already lost its metadata.
def http-meta []: any -> any {
  metadata | get -i "http.response"
}

# A client backed by real (xs) stores, provided by `http-nu eval --store`.
def test-client [] {
  {
    provider_name: "discord"
    id: "cid"
    secret: "csecret"
    redirect: "http://localhost:8080/auth/callback"
    scopes: ["identify"]
    sessions: (make-xs-store "session")
    challenges: (make-xs-store "challenge")
  }
}

# Stub provider so the callback success path never touches the network.
def stub-provider [] {
  {
    auth-url: {|client, state| $"https://provider.example/authorize?state=($state)" }
    token-exchange: {|client, code| {status: 200, body: {access_token: "at", expires_in: 3600}} }
    get-user: {|token| {status: 200, body: {id: "42", username: "neo"}} }
  }
}

# handle-oauth: 302 to the provider, sets the challenge cookie.
def test-handle-oauth [] {
  let client = test-client
  let m = (handle-oauth (stub-provider) $client "/dashboard" | http-meta)

  assert ($m.status == 302) "handle-oauth must 302"
  assert ($m.headers.Location | str starts-with "https://provider.example/authorize") "Location is the provider auth url"
  assert (($m.headers | get "Set-Cookie") | str contains "oauth_challenge=") "sets the challenge cookie"
  print "ok handle-oauth"
}

# handle-oauth-callback success: 302 to return_to, sets session + clears challenge.
def test-callback-success [] {
  let client = test-client

  # Store a challenge exactly as handle-oauth would.
  let challenge = generate-challenge "/dashboard" "discord"
  let key = ($challenge.data | to json -r | do $client.challenges.set)
  let req = {
    headers: {cookie: $"oauth_challenge=($key)"}
    query: {state: $challenge.token, code: "abc123"}
  }

  let m = (handle-oauth-callback (stub-provider) $client $req | http-meta)
  assert ($m.status == 302) "callback success must 302"
  assert ($m.headers.Location == "/dashboard") "redirects to return_to"

  let cookies = ($m.headers | get "Set-Cookie")
  assert (($cookies | length) == 2) "sets session and clears challenge (2 Set-Cookie)"
  assert ($cookies | any {|c| $c | str starts-with "session=" }) "session cookie set"
  assert ($cookies | any {|c| $c | str starts-with "oauth_challenge=" }) "challenge cookie cleared"
  print "ok callback-success"
}

# handle-oauth-callback failures each carry the right 4xx status.
def test-callback-failures [] {
  let client = test-client

  # Missing challenge cookie.
  let m1 = (handle-oauth-callback (stub-provider) $client {headers: {}, query: {}} | http-meta)
  assert ($m1.status == 400) "missing challenge cookie -> 400"

  # Well-formed but unknown challenge key.
  let ghost = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  let m2 = (handle-oauth-callback (stub-provider) $client {headers: {cookie: $"oauth_challenge=($ghost)"}, query: {state: "x"}} | http-meta)
  assert ($m2.status == 400) "unknown challenge -> 400"

  # Known challenge, wrong state token (CSRF mismatch).
  let challenge = generate-challenge "/" "discord"
  let key = ($challenge.data | to json -r | do $client.challenges.set)
  let m3 = (handle-oauth-callback (stub-provider) $client {headers: {cookie: $"oauth_challenge=($key)"}, query: {state: "wrong", code: "c"}} | http-meta)
  assert ($m3.status == 400) "state mismatch -> 400"
  print "ok callback-failures"
}

# handle-logout: 403 on bad CSRF, 302 (clearing cookies) on valid, 302 with no session.
def test-logout [] {
  let client = test-client
  let sess = {user: {id: "1"}, csrf_token: "tok-xyz", provider: "discord"}
  let key = ($sess | to json -r | do $client.sessions.set)

  # Wrong CSRF token -> 403 (does not delete the session).
  let bad = (handle-logout $client {headers: {cookie: $"session=($key)"}, query: {csrf: "nope"}} | http-meta)
  assert ($bad.status == 403) "logout with wrong csrf -> 403"

  # Valid CSRF -> 302, clears session + challenge cookies.
  let ok = (handle-logout $client {headers: {cookie: $"session=($key)"}, query: {csrf: "tok-xyz"}} | http-meta)
  assert ($ok.status == 302) "logout with valid csrf -> 302"
  assert ($ok.headers.Location == "/") "logout redirects to /"
  assert (($ok.headers | get "Set-Cookie" | length) == 2) "clears session + challenge"

  # No session at all -> idempotent 302.
  let none = (handle-logout $client {headers: {}, query: {}} | http-meta)
  assert ($none.status == 302) "logout with no session -> 302"
  print "ok logout"
}

def assert [condition: bool, message: string] {
  if not $condition {
    error make {msg: $"Assertion failed: ($message)"}
  }
}

test-handle-oauth
test-callback-success
test-callback-failures
test-logout
print "ok handlers (served-path metadata)"
