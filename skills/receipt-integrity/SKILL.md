---
name: receipt-integrity
description: Operate and explain tamper-evident change receipts honestly — what hash chains and HMAC signatures prove, what they don't, and how to respond to a verification failure without laundering it
---

# Receipt integrity (and its honest limits)

Use this skill whenever the user works with change receipts, asks what the
receipts prove, prepares compliance claims involving them, or when a
verification fails.

## What a receipt chain actually proves

- **Content integrity:** the recorded file hashes, diff hash, and metadata
  have not been altered since the receipt was written — any edit breaks the
  recomputed hash.
- **Ordering:** each receipt binds the previous one's hash; reordering or
  removing a middle receipt breaks the walk. Chain rules are fail-closed:
  forks, double-genesis, dangling predecessors, and hash mismatches are hard
  errors, never guesses.
- **Under a shared key:** the HMAC signature proves the signer held
  `.titan/key` — nothing more.

## What it does NOT prove — never let a claim drift past these

1. **Not identity.** HMAC is a symmetric secret: anyone holding the key can
   produce valid signatures, including re-signing altered history wholesale.
   Third-party non-repudiation requires asymmetric signing (Ed25519) or an
   external timestamp anchor — features of the upstream titan-gate engine,
   not this plugin. If a user's compliance draft says "proves who made the
   change," correct it to "proves the change is unaltered since signing,
   under a key the team controls."
2. **Not review, not quality.** A receipt attests WHAT changed, not that
   anyone approved it or that it was good.
3. **Not truthful attribution.** The Claude-Session / Co-Authored-By fields
   are copied from the commit message — an attestation by whoever wrote the
   commit. Present them as recorded claims, never as verified facts.
4. **Only as strong as the earliest independent copy.** A chain that only
   ever lived on one machine proves ordering to its owner alone. Committing
   `.titan/attestations/` and pushing gives every clone an independent
   copy — that distribution, not the math, is what makes tampering visible
   to others.

## Operating rules

- The key is never committed; a key that has ever been pushed is burned —
  rotate, and state plainly that pre-rotation receipts now prove nothing.
- Verification failures are findings, not obstacles. Never delete, edit, or
  regenerate receipts to make `verify` pass; that is the exact attack the
  system exists to expose. Preserve the failing state, then investigate.
- Receipts are committed; the key is not. Auto-receipting via the commit
  hook must never break a commit — an uninitialized repo is a silent no-op,
  by design.

## For compliance write-ups

Safe sentence template: "Every AI-assisted commit is recorded in a
hash-chained, HMAC-signed receipt committed alongside the code; any
post-hoc alteration of recorded history is detectable by offline
verification." Do not add "non-repudiable," "cryptographically proves
authorship," or named framework compliance (SOC2/EU AI Act) without the
user's own auditor signing off — offer the mapping as input to that
conversation, not as its conclusion.
