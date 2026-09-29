---
description: Set up tamper-evident change receipts in this repository — generate the signing key (gitignored) and prepare the attestation chain
---

Initialize receipts in the user's current repository:

```
python3 "${CLAUDE_PLUGIN_ROOT}/core/receipt.py" init
```

After it succeeds, explain the two facts the user must not learn later:

1. `.titan/key` is the shared signing key. It is gitignored and must NEVER
   be committed — receipts are only as trustworthy as this key is private.
   If they want it backed up, that backup lives outside the repo.
2. Receipts land in `.titan/attestations/` and SHOULD be committed — they
   are the audit trail and travel with the repo.

If init refuses because the key is tracked by git, that is fail-closed
working as designed: help them run `git rm --cached .titan/key`, then retry.
A key that has ever been pushed is burned — rotate it (`init --force`) and
say plainly that receipts signed with the burned key prove nothing anymore.
