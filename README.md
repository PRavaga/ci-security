# ci-security

Shared security CI for my repos. Two layers, called from one reusable workflow:

1. **Pattern guard** — a dependency-free Node runner (`scripts/security-guard.mjs`)
   that fails the build if a repo's known footguns reappear. Each repo supplies
   its own `security-guard.config.json`. No API key, no cost.
2. **AI security review** — Claude reviews the PR diff and comments findings.
   Self-skips unless a `CLAUDE_API_KEY` secret is set, and only on pull requests.

## Onboard a repo

Add **one** workflow file:

```yaml
# .github/workflows/security.yml
name: Security
on:
  pull_request:
    branches: [main]
  release:
    types: [published]
jobs:
  security:
    uses: PRavaga/ci-security/.github/workflows/security.yml@v1
    secrets: inherit
```

Then (optionally) add a `security-guard.config.json` at the repo root listing that
repo's banned/required patterns. Without one, only the AI review runs.

To enable the AI layer, add a `CLAUDE_API_KEY` secret (repo or org level). That's it.

## Guard config

`security-guard.config.json` at the repo root. See `examples/` for a real one.

```jsonc
{
  "scan": { "roots": ["src"], "extensions": [".ts", ".tsx"] },
  "forbid": [
    {
      "label": "Human-readable name of the rule",
      "pattern": "regex (matched per non-comment line)",
      "advice": "How to fix it"
    }
  ],
  "require": [
    {
      "label": "Gate that must stay present",
      "file": "path/to/file.ts",
      "pattern": "regex that must appear in that file"
    }
  ]
}
```

- `forbid` — fails if any pattern matches a non-comment line in scanned files.
- `require` — fails if any pattern is missing from its target file (catches a
  security gate being silently deleted).

Run locally: `node scripts/security-guard.mjs` from the repo root.

## Notes

- The AI review action is not hardened against prompt injection — it's gated to
  not run on forked PRs (no secret available there), so only trusted diffs reach it.
- Model is pinned to `claude-opus-4-8` by default; override per-repo with the
  `claude-model` input, or pin `claude-sonnet-4-6` for cheaper runs.
