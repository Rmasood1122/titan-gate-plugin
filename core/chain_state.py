"""Chain-head discovery for Titan Gate writers — the ONE way to learn prev.

WO-3 item 2. Writers call latest_receipt_hash(receipts_root) and use the
result as the new receipt's prev_receipt_hash. Callers never assert their
own prev: a caller who can set prev can fork the chain by construction.

Design decisions (logged):
- No HEAD pointer file: a pointer is a second source of truth that can lie.
  We scan and reconstruct linkage every time — O(n) per write, honest.
- Any ambiguity is a hard error, never a guess: fork, double-genesis,
  dangling prev, hash mismatch, or headlessness all raise ChainStateError.
  Writing on top of a broken chain would launder the break.
"""
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

import sys as _sys
from pathlib import Path as _P
_sys.path.insert(0, str(_P(__file__).resolve().parent))
from canonical import canonical_bytes, canonical_bytes_jcs, JCSError

GENESIS = "GENESIS"


class ChainStateError(Exception):
    """The persisted chain is absent where required, forked, or invalid."""


def _recomputed_hash(receipt: Dict[str, Any]) -> str:
    """Per-profile hash recompute (SPEC-2 s1.3: canonicalizations are
    profile-bound and non-interchangeable; schema_version selects).

    receipt_v1 / absent: TRS-1 sorted-keys path, byte-identical to
    pre-WO-3.5 behavior (field exclusion lives inside canonical_bytes,
    golden-pinned). receipt_trs2_v1: SHA-256 over JCS(body), body =
    receipt minus sig and stored receipt_hash (mirrors trs2_writer).
    Unknown versions hard-error: a walker that silently falls back to
    a default canonicalization is a verifier that can be steered.
    """
    profile = receipt.get("schema_version", "receipt_v1")
    if profile in ("receipt_v1", "change-attestation/v1"):
        # change-attestation/v1 (plugin profile): TRS-1 sorted-keys
        # canonicalization, same exclusion set — chain rules identical.
        return hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    if profile in ("receipt_trs2_v1", "receipt_trs2_v2"):
        # v2 (WO-6): identical body recompute — receipt_type lives inside
        # the body, so the same exclusion covers both TRS-2 profiles.
        body = {k: v for k, v in receipt.items()
                if k not in ("sig", "receipt_hash")}
        try:
            return hashlib.sha256(canonical_bytes_jcs(body)).hexdigest()
        except JCSError as e:
            raise ChainStateError(
                f"TRS-2 receipt not JCS-canonicalizable: {e}") from e
    raise ChainStateError(
        f"unknown schema_version {profile!r}: no canonicalization "
        f"fallback exists by design")


def latest_receipt_hash(receipts_root) -> str:
    """Return the chain head's receipt_hash, or GENESIS for an empty tree.

    Scans all *.json under receipts_root (recursively), validates that they
    form exactly one unbroken chain from a single GENESIS receipt, and
    returns the hash of the unique receipt no other receipt links to.
    """
    root = Path(receipts_root)
    paths = sorted(root.rglob("*.json")) if root.exists() else []
    if not paths:
        return GENESIS

    receipts = []
    profiles = set()
    for p in paths:
        try:
            r = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise ChainStateError(f"unreadable receipt {p}: {e}") from e
        stored = r.get("receipt_hash")
        prev = r.get("prev_receipt_hash")
        if not stored or not prev:
            raise ChainStateError(
                f"receipt {p} missing receipt_hash/prev_receipt_hash")
        profiles.add(r.get("schema_version", "receipt_v1"))
        if len(profiles) > 1:
            raise ChainStateError(
                f"mixed profiles in one tree {sorted(profiles)} at {p}: "
                f"a chain has ONE profile, declared at genesis (SPEC-2 s1.3)")
        if _recomputed_hash(r) != stored:
            raise ChainStateError(
                f"receipt {p}: stored receipt_hash does not match recomputed "
                f"hash — refusing to extend a tampered chain")
        receipts.append((p, r))

    by_hash = {}
    prev_refs: Dict[str, list] = {}
    for p, r in receipts:
        h = r["receipt_hash"]
        if h in by_hash:
            raise ChainStateError(f"duplicate receipt_hash {h} ({p})")
        by_hash[h] = (p, r)
        prev_refs.setdefault(r["prev_receipt_hash"], []).append(p)

    genesis_children = prev_refs.get(GENESIS, [])
    if len(genesis_children) == 0:
        raise ChainStateError("no GENESIS receipt: chain has no root")
    if len(genesis_children) > 1:
        raise ChainStateError(
            f"multiple receipts claim prev=GENESIS: {genesis_children} — "
            f"forked at root (or a pre-WO-3 legacy tree; migrate it first)")

    for prev, children in prev_refs.items():
        if len(children) > 1:
            raise ChainStateError(f"fork: {children} all claim prev={prev}")
        if prev != GENESIS and prev not in by_hash:
            raise ChainStateError(
                f"dangling prev {prev} referenced by {children[0]}: "
                f"predecessor receipt is missing")

    heads = [h for h in by_hash if h not in prev_refs]
    if len(heads) != 1:
        raise ChainStateError(
            f"expected exactly one chain head, found {len(heads)}")
    return heads[0]
