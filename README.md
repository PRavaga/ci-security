# ci-security

Security checks I reuse across my repos, set up once here so each repo only needs a few lines to opt in.

Two parts:

- A pattern guard. A small Node script that fails the build when a known footgun shows up in a repo's code. Each repo says what to watch for in its own `security-guard.config.json`. No API key, runs in a few seconds.
- An AI review. Claude reads the pull request diff and leaves comments. It only runs when a `CLAUDE_API_KEY` secret exists, so it stays quiet (and green) until you set one up, and it never runs on forked PRs.

## Attach it to a repo

Add one workflow file:

```yaml
# .github/workflows/security.yml
name: Security
on:
  pull_request:
    branches: [main]
  release:
    types: [published]
permissions:
  contents: read
  pull-requests: write
jobs:
  security:
    uses: PRavaga/ci-security/.github/workflows/security.yml@v1
    secrets: inherit
```

That's the whole hookup. The next PR gets the guard, plus the AI review once a key is set. `secrets: inherit` is what passes `CLAUDE_API_KEY` through.

## Tell the guard what to catch

Drop a `security-guard.config.json` at the repo root. Leave it out and you just get the AI review.

```jsonc
{
  "scan": { "roots": ["src"], "extensions": [".ts", ".tsx"] },
  "forbid": [
    {
      "label": "what the rule is",
      "pattern": "regex, checked per non-comment line",
      "advice": "how to fix it (printed when it trips)"
    }
  ],
  "require": [
    {
      "label": "a gate that has to stay in place",
      "file": "src/path/to/file.ts",
      "pattern": "regex that must appear in that file"
    }
  ]
}
```

`forbid` trips when a pattern shows up where it shouldn't. `require` trips when a pattern goes missing, which is how you stop someone quietly deleting a security check. There's a working example in `examples/`.

Run it locally from the repo root:

```bash
# if the repo keeps its own copy of the runner
node scripts/security-guard.mjs

# or pull the canonical one and run it against the current repo
curl -fsSL https://raw.githubusercontent.com/PRavaga/ci-security/v1/scripts/security-guard.mjs | node --input-type=module
```

## Turn on the AI review

Add a `CLAUDE_API_KEY` secret. Use an org-level secret for a group of repos so there's one place to rotate it, or a repo/account secret for a one-off. The review starts commenting on the next PR. Nothing else to change.

Two knobs, passed as inputs on the caller if you want them:

- `claude-model` defaults to `claude-opus-4-8`. Switch to `claude-sonnet-4-6` on busy repos to spend less.
- `exclude-directories` defaults to `build,node_modules,.context`.

## Worth knowing

- The review action isn't hardened against prompt injection, so it's blocked on forked PRs (no secret reaches them anyway). Only diffs you trust get reviewed.
- This repo is public on purpose. A workflow here can only be called from repos under my other accounts if it's public.
- Pin to `@v1`. I keep that tag on a version I've checked.
