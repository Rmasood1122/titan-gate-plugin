---
description: Verify the full receipt chain offline — structure (single unbroken chain from GENESIS, content hashes) and every HMAC signature; --structure-only when no key is present
argument-hint: "[--structure-only]"
---

Verify everything:

```
python3 "${CLAUDE_PLUGIN_ROOT}/core/receipt.py" verify $ARGUMENTS
```

Report the result exactly as it is:

- **PASS** means: every receipt's content is unchanged since signing, the
  chain is a single unbroken line from GENESIS, and every signature checks
  out under the repo's key. Include the tool's own caveat when you relay
  the result: PASS does not identify WHO signed — HMAC is a shared secret.
- **PASS (structure only)** means the chain and content hashes are
  consistent but signatures were NOT checked because no key was available.
  Relay that limitation verbatim; it is a weaker claim.
- **CHAIN FAIL / SIG FAIL** names the exact receipt. Do not delete or edit
  it to get to green; the failure IS the finding. Help the user diff the
  offending receipt against git history to see what changed and when.

This runs fully offline — no network, no service, just the files and the key.
