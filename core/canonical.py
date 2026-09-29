"""Canonical serialization for Titan Gate receipts — the ONE definition.

Extracted in WO-3 from the duplicated copies in api/receipt_signing.py and
titan_gate/verify.py (which were byte-identical but independently maintained;
the stale-verify.py incident proved that duplication can diverge silently).
Both writer and verifier import from here. Do not redefine these symbols
anywhere else — tests/test_wo3_canonical_module.py enforces this by identity.

TRS-1 semantics, golden-pinned: sorted-keys compact JSON, UTF-8, with
signature-adjacent fields excluded from the signed/hashed body.
TRS-2 (JCS/RFC 8785) will be added here as a separate function, never by
modifying this one.
"""
import json
from typing import Any, Dict

EXCLUSION_FIELDS = {"signature", "receipt_hash", "prev_receipt_hash_verified", "_debug", "_meta"}


def canonical_bytes(receipt: Dict[str, Any]) -> bytes:
    filtered = {k: v for k, v in receipt.items() if k not in EXCLUSION_FIELDS}
    return json.dumps(
        filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# TRS-2: RFC 8785 (JCS) canonicalization — WO-3.4b
#
# TRS-1's sorted-keys canonicalization above is golden-pinned and MUST NOT
# be modified. This section is additive only.
#
# Domain restriction (normative, SPEC.md v2): TRS-2 admits no non-integer
# numbers, and integers must lie within +/-(2^53 - 1). Within that domain,
# output is byte-identical to full RFC 8785 JCS. Rationale: ECMAScript
# float serialization cannot be reproduced byte-perfectly from Python;
# excluding floats from the value domain removes the divergence class
# entirely rather than approximating it.
# ---------------------------------------------------------------------------

_JCS_MAX_SAFE_INT = 2**53 - 1

# Two-char escape shorthands required by RFC 8785 s3.2.2.2
_JCS_SHORTHANDS = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
    0x22: '\\"', 0x5C: "\\\\",
}


class JCSError(ValueError):
    """Value outside the TRS-2 JCS domain, or not JSON-serializable."""


def _jcs_escape_string(s: str) -> str:
    out = []
    for ch in s:
        cp = ord(ch)
        if cp in _JCS_SHORTHANDS:
            out.append(_JCS_SHORTHANDS[cp])
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)  # incl. U+007F and all non-ASCII: literal UTF-8
    return "".join(out)


def _jcs_serialize(value) -> str:
    # bool before int: isinstance(True, int) is True in Python
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return '"' + _jcs_escape_string(value) + '"'
    if isinstance(value, float):
        raise JCSError(
            f"non-integer number {value!r} is outside the TRS-2 JCS domain"
        )
    if isinstance(value, int):
        if not -_JCS_MAX_SAFE_INT <= value <= _JCS_MAX_SAFE_INT:
            raise JCSError(
                f"integer {value} outside IEEE-754 safe range "
                f"+/-(2^53-1); outside the TRS-2 JCS domain"
            )
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(_jcs_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise JCSError(f"object key must be str, got {type(k).__name__}")
        # RFC 8785 s3.2.3: keys sort by UTF-16 code units. Byte-wise
        # comparison of UTF-16-BE encodings is exactly code-unit order
        # (Python's default str sort is codepoint order and diverges
        # for non-BMP keys).
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(
            '"' + _jcs_escape_string(k) + '":' + _jcs_serialize(v)
            for k, v in items
        ) + "}"
    raise JCSError(
        f"type {type(value).__name__} is not JSON-serializable "
        f"(tuples, bytes, sets etc. rejected — no silent coercion)"
    )


def canonical_bytes_jcs(value) -> bytes:
    """RFC 8785 (JCS) canonical bytes over the TRS-2 value domain.

    Raises JCSError for floats, integers beyond +/-(2^53-1), non-str
    object keys, and any non-JSON type. Within the admitted domain the
    output is byte-identical to full RFC 8785.
    """
    return _jcs_serialize(value).encode("utf-8")
