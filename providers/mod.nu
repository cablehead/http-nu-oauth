# OAuth Providers Registry
# Aggregates all OAuth provider implementations

use ./discord
use ./google

# Get all available OAuth providers
export def all [] {
  {
    discord: (discord provider)
    google: (google provider)
  }
}
