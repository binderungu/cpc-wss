"""Small, side-effect-free value/encoding primitives for WSS sidecars.

This encoding is ``wss-workflow-json-v1``.  It is not an alternative CPC
validator, signer, trust source, or native-use observer.  Importing this module
does not read files, inspect environment variables, or generate evidence.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Any, Collection


class ContractError(ValueError):
    """Malformed workflow data; not a CPC admission disposition."""


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INSTANT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)
_MAX_DEPTH = 64


def require_text(
    value: object,
    field: str,
    *,
    allow_empty: bool = False,
    max_chars: int | None = None,
) -> str:
    if not isinstance(value, str):
        raise ContractError(f"{field}: expected a string")
    if not allow_empty and not value:
        raise ContractError(f"{field}: empty string")
    if max_chars is not None and len(value) > max_chars:
        raise ContractError(f"{field}: string exceeds supported length")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ContractError(f"{field}: unsupported Unicode") from exc
    return value


def require_identifier(value: object, field: str) -> str:
    text = require_text(value, field, max_chars=256)
    if text != text.strip() or not text.strip():
        raise ContractError(f"{field}: expected a nonblank trimmed identifier")
    if any(unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in text):
        raise ContractError(f"{field}: identifier contains control characters")
    return text


def optional_identifier(value: object, field: str) -> str | None:
    return None if value is None else require_identifier(value, field)


def require_int(value: object, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ContractError(f"{field}: expected an integer in the supported range")
    return value


def require_bool(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise ContractError(f"{field}: expected a boolean")
    return value


def require_digest(value: object, field: str) -> str:
    text = require_text(value, field)
    if _DIGEST.fullmatch(text) is None:
        raise ContractError(f"{field}: expected sha256 and 64 lowercase hex digits")
    return text


def require_rfc3339(value: object, field: str) -> str:
    """Validate supported syntax before datetime can normalize invalid offsets."""
    text = require_text(value, field)
    if _INSTANT.fullmatch(text) is None:
        raise ContractError(f"{field}: expected an explicit-zone RFC3339 instant")
    try:
        instant = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
        if instant.utcoffset() is None:
            raise ValueError("timezone absent")
    except (ValueError, OverflowError) as exc:
        raise ContractError(f"{field}: invalid or unsupported instant") from exc
    return text


def require_mapping(
    value: object,
    field: str,
    *,
    required: Collection[str] = (),
    optional: Collection[str] = (),
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{field}: expected an object")
    if any(not isinstance(k, str) for k in value):
        raise ContractError(f"{field}: object keys must be strings")
    required_keys, optional_keys = set(required), set(optional)
    keys = set(value)
    if required_keys - keys:
        raise ContractError(f"{field}: required field absent")
    if keys - required_keys - optional_keys:
        raise ContractError(f"{field}: unsupported field")
    return dict(value)


def freeze_json(value: object, field: str = "$") -> Any:
    """Copy into immutable JSON values; reject floats, cycles and surrogates.

    The depth limit is a workflow-container bound, not CPC's root-zero depth
    rule.  JSON object keys are data; this helper performs no authority checks.
    """
    return _freeze(value, field, 0, set())


def _freeze(value: object, field: str, depth: int, active: set[int]) -> Any:
    if depth > _MAX_DEPTH:
        raise ContractError(f"{field}: workflow value exceeds supported depth")
    if value is None or type(value) in {bool, int}:
        return value
    if isinstance(value, str):
        return require_text(value, field, allow_empty=True)
    if not isinstance(value, (Mapping, list, tuple)):
        raise ContractError(f"{field}: unsupported JSON type (including floats)")
    identity = id(value)
    if identity in active:
        raise ContractError(f"{field}: cyclic workflow value")
    active.add(identity)
    try:
        if isinstance(value, Mapping):
            frozen: dict[str, Any] = {}
            for key, item in value.items():
                key = require_text(key, field + ".key", allow_empty=True)
                frozen[key] = _freeze(item, field + ".value", depth + 1, active)
            return MappingProxyType(frozen)
        return tuple(_freeze(item, field + "[]", depth + 1, active) for item in value)
    finally:
        active.remove(identity)


def plain_json(value: object) -> Any:
    """Return an independent, mutable representation of supported JSON data."""
    return _plain(freeze_json(value))


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def canonical_json_bytes(value: object) -> bytes:
    """Encode a workflow value deterministically; does not sign or attest it."""
    return json.dumps(
        plain_json(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("JSON: duplicate object key")
        result[key] = value
    return result


def _unsupported_number(_text: str) -> Any:
    raise ContractError("JSON: floating-point/nonfinite values are unsupported")


def decode_json_object(raw: str | bytes, field: str = "$") -> dict[str, Any]:
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ContractError(f"{field}: invalid UTF8 transport") from exc
    elif isinstance(raw, str):
        text = require_text(raw, field, allow_empty=True)
    else:
        raise ContractError(f"{field}: expected raw UTF8 bytes or text")
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except ContractError:
        raise
    except (ValueError, RecursionError, OverflowError) as exc:
        raise ContractError(f"{field}: malformed or unsupported JSON transport") from exc
    if not isinstance(decoded, dict):
        raise ContractError(f"{field}: expected a JSON object")
    return plain_json(decoded)
