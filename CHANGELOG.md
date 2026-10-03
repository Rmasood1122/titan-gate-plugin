# Changelog

## 1.1.0 — 2026-10-03

Positioning: an audit trail for AI-written code, with the provenance auditors
actually ask about.

- **Provenance block** on every receipt: `ai_assisted` with its `basis`
  (commit trailers and/or the Claude Code hook), `recorder`, and — when
  written by the Claude Code hook — `session_id`, `tool_use_id`,
  `permission_mode`, `models` and `claude_code_version` read from the session
  transcript, plus the transcript's line count and sha256 at receipt time.
  All signed; flipping `ai_assisted` breaks verification. Environment is
  trusted only when `CLAUDECODE` is set.
- **Commit author and timestamp** recorded (`commit.author`, `commit.committed_at`).
- **Full coverage**: `init` vendors the verifier into `.titan/tools/` and
  installs a git `post-commit` hook, so human commits are receipted too
  (`ai_assisted: false`). The git hook defers inside Claude Code so the richer
  receipt wins; it never fails a commit. `install-hook` re-installs per clone;
  `init --no-git-hook` opts out.
- **`/receipt-report`**: markdown evidence — receipted commits, AI-assisted
  share, by recorder / author / month, models and tool versions, chain
  verification result, and a mandatory what-it-does-not-prove footer. v1.0
  receipts (no provenance) are reported as "unknown", never as human.
- **`verify --structure-only`**: chain + content hashes without the key, for
  CI clones that don't hold the secret; output states signatures were not checked.
- **GitHub Action** (`action.yml`): `uses: Rmasood1122/titan-gate-plugin@v1.1.0`
  with optional `key` secret and `report` path.
- README rewritten around the problem with a real receipt; limits in a
  collapsed section, expanded (coverage, recorded-claims). Skill updated to match.
- Suite: 44 tests (was 25).

## 1.0.0

- Initial release: hash-chained HMAC receipts, fail-closed chain rules,
  PostToolUse auto-receipting, offline verification, receipt-integrity skill.
