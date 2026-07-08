# CLAUDE.md

## Prose style

Applies to all writing here: READMEs, code comments, commit and PR text.

- Say the thing. Cut lead-ins that announce structure instead of delivering it
  ("Two clocks, kept separate on purpose:", "It's worth noting that"). Start
  with the content; let a heading or table carry the framing.
- Every word earns its place. Cut to about half your first draft.
- Glanceable over prose. Prefer tables and short bullets a reader can scan.
- State each fact once. If two sections would repeat it, pick the right home and
  link.
- Don't oversell. Drop "robust", "seamless", "simply", "not just documented".
  Write claims a reader can check.
- Plain ASCII only. No em-dashes (use a comma, colon, or period). No Unicode
  arrows or ellipsis; write `->` and `...`.
- Docs order: what it is, how it works, usage, then reference. File layout and
  requirements go last.

## Naming

- Name for a newcomer, not for the spec. `challenge` beats `state` for the CSRF
  record; `persistent` / `expiring` beats `long-lived` / `ephemeral`.
- Keep the spec term only where it is the wire contract. The OAuth `state` query
  parameter stays `state`; the app-side concept it carries is a `challenge`.

## Commit messages

- Conventional prefix (`fix:`, `refactor:`, `docs:`), subject <= 80 chars.
- No `Co-Authored-By` trailer (`.claude/settings.json` sets
  `includeCoAuthoredBy` to false).
- Describe the change, not the process.
