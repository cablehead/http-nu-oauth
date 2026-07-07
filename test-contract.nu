#!/usr/bin/env nu
# Shared, table-driven store-interface contract suite.
#
# The SAME assertions run against every implementation of the storage interface
# (see lib.nu "Storage interface"). It is executed via http-nu so the xs store
# commands (.append/.last/.cas/.cat/.remove) are available:
#
#   http-nu eval --store <dir> test-contract.nu
#
# The file store needs no store commands, so it runs here too; both impls go
# through the exact same suite. `nu test.nu` drives this file (see test.nu).

use lib.nu *

# A well-formed but never-minted key (valid shape, absent).
const UNKNOWN_KEY = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

# Keys that must be rejected at the boundary (traversal / topic injection / bad
# shape). None may read, write, or delete anything.
const BAD_KEYS = [
  "../../etc/passwd"   # path traversal
  "*"                  # xs topic wildcard
  "a.b"                # xs topic separator
  "session.deadbeef"   # topic injection
  ""                   # empty
  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # 62 non-hex
]

# Run the full contract against one store `impl`, plus a ttl-configured store
# `ttl_impl` (short ttl) to prove native expiry. `wait` is slept before the
# expiry check.
def run-suite [label: string, impl: record, ttl_impl: record, wait: duration] {
  # set mints an opaque 64-hex key.
  let k = ('{"v":1}' | do $impl.set)
  assert ($k | valid-store-key) $"($label): set returns a valid opaque key"

  # get round-trips the stored value exactly.
  assert ((do $impl.get $k) == '{"v":1}') $"($label): get returns stored value"

  # update overwrites the value at the same key.
  '{"v":2}' | do $impl.update $k
  assert ((do $impl.get $k) == '{"v":2}') $"($label): update overwrites at key"

  # delete removes; get then yields null (not an error).
  do $impl.delete $k
  assert ((do $impl.get $k) == null) $"($label): get after delete is null"

  # A well-formed but unknown key: get null, delete/update are silent no-ops.
  assert ((do $impl.get $UNKNOWN_KEY) == null) $"($label): unknown key -> null"
  "nope" | do $impl.update $UNKNOWN_KEY
  do $impl.delete $UNKNOWN_KEY

  # Malformed keys must be rejected everywhere and must NOT touch a real entry.
  let guard = ('{"keep":true}' | do $impl.set)
  for bad in $BAD_KEYS {
    assert ((do $impl.get $bad) == null) $"($label): malformed key get -> null: ($bad)"
    "pwned" | do $impl.update $bad
    do $impl.delete $bad
  }
  assert ((do $impl.get $guard) == '{"keep":true}') $"($label): malformed ops must not touch a real entry"
  do $impl.delete $guard

  # Native TTL: an entry is readable before expiry and null after.
  let tk = ('ephemeral' | do $ttl_impl.set)
  assert ((do $ttl_impl.get $tk) == 'ephemeral') $"($label): ttl entry readable before expiry"
  sleep $wait
  assert ((do $ttl_impl.get $tk) == null) $"($label): ttl entry expired to null"

  print $"ok contract:($label)"
}

def assert [condition: bool, message: string] {
  if not $condition {
    error make {msg: $"Assertion failed: ($message)"}
  }
}

# --- Run the shared suite against BOTH implementations -----------------------

# File-backed impl (ttl expressed as a nushell duration).
run-suite "file" (
  make-simplefile-store (mktemp -d)
) (
  make-simplefile-store (mktemp -d) --ttl 400ms
) 900ms

# xs (cross.stream) impl (ttl expressed as a native xs frame ttl string).
run-suite "xs" (
  make-xs-store "session"
) (
  make-xs-store "state" --ttl "time:400"
) 900ms

print "ok store-contract (file + xs)"
