# ci-security

Security checks I reuse across my repos, set up once here so each repo only needs a few lines to opt in.

Two parts:

- A pattern guard. A small Node script that fails the build when a known footgun shows up in a repo's code. Each repo says what to watch for in its own `security-guard.config.json`. No API key, runs in a few seconds. It's a regression tripwire for known bugs, not a real analysis — pair it with CodeQL/Semgrep and the AI review.
- An AI review. Claude reads the pull request diff and leaves comments. It only runs when a `CLAUDE_API_KEY` secret exists, so it stays quiet (and green) until you set one up, and it never runs on forked PRs.

## Attach it to a repo

Add one workflow file. **Pin an immutable ref** (a full commit SHA or a `vX.Y.Z` release tag) — never a moving tag — and pass only the one secret:

```yaml
# .github/workflows/security.yml
name: Security
on:
  pull_request:
    branches: [main]   # use [master] if that's the default branch
  release:
    types: [published]
permissions:
  contents: read
  pull-requests: write
jobs:
  security:
    uses: PRavaga/ci-security/.github/workflows/security.yml@v1.0.1
    secrets:
      CLAUDE_API_KEY: ${{ secrets.CLAUDE_API_KEY }}
```

For the pattern guard, also **vendor the runner** — copy `scripts/security-guard.mjs` from this repo (at the tag you pinned) into your repo, alongside your `security-guard.config.json`. The CI runs your vendored copy; nothing is fetched from the network at run time. Re-copy it when you bump the pinned version. Without a vendored runner (and with a config present) the guard fails loudly so you don't get a silent no-op.

That's the whole hookup. The next PR gets the guard, plus the AI review once a key is set.

Two reasons not to use the old shortcuts:
- **No `secrets: inherit`.** It forwards *every* secret in the repo to this workflow, and it doesn't pass across owners (an org repo calling this personal repo gets nothing). Map `CLAUDE_API_KEY` explicitly, as above — that's least-privilege and works cross-owner.
- **No moving `@v1`.** Pin a SHA or a `vX.Y.Z` tag and bump deliberately (Dependabot can do it). A moving tag means any change here runs in your repo with no review on your side.

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
      "pattern": "regex that must appear on a code line in that file"
    }
  ]
}
```

`forbid` trips when a pattern shows up where it shouldn't. `require` trips when a pattern is missing from a non-comment line of the target file, which is how you catch someone quietly deleting a security check (a comment mentioning the symbol does not satisfy it). There's a working example in `examples/`.

Run it locally from the repo root. Don't pipe it from the network — copy the runner in (vendor it) or run it from a clone pinned to a release tag:

```bash
node scripts/security-guard.mjs            # vendored copy
# or from a pinned clone of this repo:
node /path/to/ci-security/scripts/security-guard.mjs   # checked out at vX.Y.Z
```

## Turn on the AI review

Add a `CLAUDE_API_KEY` secret (org-level for a group of repos, or per-repo). Use a **dedicated, budget-capped** key for CI — not a key you use elsewhere — so a leak is cheap to rotate and a runaway run can't drain your whole budget. The review starts commenting on the next PR.

Inputs you can pass on the caller:

- `claude-model` — defaults to `claude-sonnet-4-6` (cheap, for the high-frequency PR tier).
- `exclude-directories` — defaults to `build,node_modules,.context,dist`.
- `max-changed-lines` — defaults to `5000`; PRs bigger than this skip the AI review to bound cost.

## Worth knowing

- **Trusted PRs only.** The review action runs Claude Code with shell access over the PR's content and isn't hardened against prompt injection. It's gated to non-fork PRs (forks get no secret), but a malicious *internal* branch still reaches it — protect who can push branches.
- **Public-repo disclosure.** Anything CI emits on a public repo (logs, artifacts, issues) is public. Don't auto-publish raw security findings on a public repo — a deep-audit report or a discovered secret would be handed to attackers. Keep raw findings private (private advisory / restricted store).
- **Releases don't gate.** `release: published` fires after the release is public, so a check there is detection, not prevention. Gate the deep audit on the pre-release PR if you want it to actually block.
- Pin a SHA or `vX.Y.Z`. The `v1` tag still exists for now but is deprecated — don't pin it.
