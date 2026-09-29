---
description: Write a signed, chained receipt for the current commit — file hashes, diff hash, and Claude session attribution from the commit trailers
---

Create a receipt for HEAD:

```
python3 "${CLAUDE_PLUGIN_ROOT}/core/receipt.py" create
```

- One receipt per commit: re-running on the same HEAD is a no-op, not a
  duplicate.
- "refusing to extend a broken chain" is fail-closed working as designed —
  something in `.titan/attestations/` was altered or lost. Run
  `/verify-chain` to locate it; NEVER "fix" a broken chain by deleting or
  editing receipts to make verification pass — that is exactly the
  tampering receipts exist to expose. The honest path is: keep the broken
  chain as evidence, investigate what changed, and if the chain must
  restart, start a new tree and say so in the commit message.
- Attribution is copied verbatim from the commit's Co-Authored-By and
  Claude-Session trailers. It is an attestation by the commit author, not
  a proof of authorship — never present it as more.

If the repo isn't initialized, offer `/receipt-init` instead of improvising.
