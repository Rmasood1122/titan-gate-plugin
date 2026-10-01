# Titan Receipts

[![CI](https://github.com/Rmasood1122/titan-gate-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/Rmasood1122/titan-gate-plugin/actions/workflows/ci.yml)

**Tamper-evident receipts for AI-assisted commits — hash-chained, signed,
verifiable offline.**

AI now writes a large share of many teams' code. When someone asks "what
did the AI change, and can you prove that record hasn't been rewritten?",
most teams have process docs. This plugin gives you receipts.

Every commit gets a receipt: the changed files and their hashes, the diff
hash, the branch and SHA, and the Claude session attribution from the
commit trailers — chained to the previous receipt and HMAC-signed. The
chain is fail-closed: forks, missing links, and edited receipts are hard
verification failures, never warnings.

## Install

Requires [Claude Code](https://claude.com/claude-code), Python 3.10+, and git.
Nothing else — stdlib only, no packages, no network, no service, nothing
phones home.

In Claude Code:

```
/plugin marketplace add Rmasood1122/titan-gate-plugin
/plugin install titan-receipts@titan-receipts-marketplace
```

Or from your shell, no session needed (same result):

```bash
claude plugin marketplace add Rmasood1122/titan-gate-plugin
claude plugin install titan-receipts@titan-receipts-marketplace
```

**Confirm it took:** `/plugin list` shows `titan-receipts`, and `/receipt-init`
is recognized as a command. If a slash command isn't recognized, start a
fresh Claude Code session — plugins load at startup.

## Commands

| Command | What it does |
|---|---|
| `/receipt-init` | Generates the repo's signing key (gitignored, never committed — and init refuses to proceed if git tracks it) |
| `/receipt` | Writes a signed, chained receipt for HEAD. One per commit; re-runs are no-ops |
| `/verify-chain` | Walks the whole chain offline: structure + every signature. Any tamper = exit 1 naming the receipt. Ends with an `ANCHOR` line: how many receipts are committed **and pushed** |

Plus a commit hook: once a repo is initialized, every `git commit` made in
a Claude session gets a receipt automatically. Uninitialized repos are a
silent no-op — the hook can never break a commit.

## What a receipt proves — exactly, no more

**Proves:** the recorded content (file hashes, diff hash, metadata) is
unchanged since signing, and the receipts form one unbroken ordered chain —
under a key your team controls.

**Does not prove:** who held the key (HMAC is a shared secret; asymmetric
signing and external timestamp anchoring are features of the upstream
[titan-gate](https://github.com/Rmasood1122/titan-gate) engine, not this
plugin); that anyone reviewed the change; or that the attribution trailer
is truthful — it is copied verbatim from the commit message as an
attestation. The bundled skill will keep your compliance language inside
these lines, because a receipt system that overclaims is worse than none.

The chain becomes evidence *to others* when `.titan/attestations/` is
committed and pushed — every clone then holds an independent copy that
tampering would have to chase down. Because that distribution is the only
defence against someone who holds the key, `/verify-chain` measures it: its
closing `ANCHOR` line reports how many receipts are untracked, uncommitted,
or committed-but-not-pushed. A chain that verifies but sits only on one
machine is a claim, not evidence.

### Verifying a clone that has no key

The key is gitignored and never travels with the repo, so a reviewer's fresh
clone has the receipts but not `.titan/key`. `/verify-chain` still runs the
full structural walk there — one unbroken chain from GENESIS, every stored
`receipt_hash` recomputed from content — and reports that result, then says
plainly `SIGNATURES NOT CHECKED` and exits 2. Structure proves the files are
internally consistent; only the key proves they were signed under it. Share
the key out-of-band with whoever needs to verify signatures.

## First run

Open Claude Code **inside the repository you want receipts for**, then:

```
/receipt-init                                         # one-time: creates the signing key (gitignored)
git commit -m "feat: something Claude helped write"   # the hook receipts it automatically
/verify-chain                                         # walks the chain — exit 0 means intact
```

That's the whole loop. Receipts land in `.titan/attestations/`; commit and
push that directory to make the chain evidence to others, not just to you.

## Provenance

The canonicalization and chain-walk rules are vendored byte-compatible from
[titan-gate](https://github.com/Rmasood1122/titan-gate) (849 tests), whose
TRS receipt engine adds Ed25519 signing, RFC-3161 timestamping, Merkle
roots, and a scoring judge. This plugin is the lightweight attestation
profile of that system: `change-attestation/v1`, with its own verifier and
its own tree — it does not claim judge-receipt compatibility, because
receipts here carry no scores. Related:
[eval-conductor](https://github.com/Rmasood1122/eval-conductor) — fail-closed
eval release gates by the same author.

## License

MIT
