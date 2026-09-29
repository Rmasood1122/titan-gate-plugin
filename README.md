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

## Commands

| Command | What it does |
|---|---|
| `/receipt-init` | Generates the repo's signing key (gitignored, never committed — and init refuses to proceed if git tracks it) |
| `/receipt` | Writes a signed, chained receipt for HEAD. One per commit; re-runs are no-ops |
| `/verify-chain` | Walks the whole chain offline: structure + every signature. Any tamper = exit 1 naming the receipt |

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
tampering would have to chase down.

## Quickstart

```
/receipt-init
git commit -m "feat: something Claude helped write"   # hook receipts it
/verify-chain
```

Requirements: Python 3.10+, git. Stdlib only — no packages, no network,
no service, nothing phones home.

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
