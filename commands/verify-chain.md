---
description: Verify the full receipt chain offline — structure (single unbroken chain from GENESIS) and every HMAC signature
---

Verify everything:

```
python3 "${CLAUDE_PLUGIN_ROOT}/core/receipt.py" verify
```

Report the result exactly as it is:

- **PASS** means: every receipt's content is unchanged since signing, the
  chain is a single unbroken line from GENESIS, and every signature checks
  out under the repo's key. Include the tool's own caveat when you relay
  the result: PASS does not identify WHO signed — HMAC is a shared secret.
- **CHAIN FAIL / SIG FAIL** names the exact receipt. Do not delete or edit
  it to get to green; the failure IS the finding. Help the user diff the
  offending receipt against git history to see what changed and when.

This runs fully offline — no network, no service, just the files and the key.
