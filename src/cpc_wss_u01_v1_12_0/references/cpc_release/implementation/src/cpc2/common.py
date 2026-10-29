"""Shared local-only wire primitives. No capture, inference, fixtures or network."""
from __future__ import annotations
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

TIME_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$')
DIGEST_RE = re.compile(r'^sha256:[0-9a-f]{64}$')
MAC_RE = re.compile(r'^hmac-sha256:[0-9a-f]{64}$')
CONTRACT_VERSION = '2.0.1'
SCHEMA_VERSION = 'cpc-2.0.1'

def iter_json_nodes(value):
    """CPC2.0.1 decoded tree: root0; key/value/item edges each add one.

    Scalar leaves and empty containers are nodes. Object keys and values are
    siblings; text/encoding length adds no tree edge. Raw JSON has no cycles.
    """
    stack = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        yield current, depth
        if isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
            stack.extend((key, depth + 1) for key in current)

def json_depth(value):
    """Full maximum edge depth including scalar leaves, not container count."""
    return max(depth for _, depth in iter_json_nodes(value))

def is_identifier(value: Any, maximum: int = 256) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= maximum and value == value.strip()
            and not any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in value))

def parse_time(value: Any):
    if not isinstance(value, str) or not TIME_RE.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        # Python datetime precision is microseconds. Reject precision it cannot
        # faithfully represent, instead of silently truncating observed order.
        fraction = re.search(r'\.(\d+)', value)
        if fraction and len(fraction.group(1)) > 6 and any(c != '0' for c in fraction.group(1)[6:]):
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError, TypeError):
        return None

def _wire_values(value: Any) -> None:
    if value is None or type(value) is bool or isinstance(value, str):
        return
    if type(value) is int and value >= 0:
        return
    if isinstance(value, list):
        for item in value: _wire_values(item)
        return
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        for item in value.values(): _wire_values(item)
        return
    raise ValueError('unsupported_wire_value')

def canonical_json(value: Any) -> bytes:
    _wire_values(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')

def digest(value: Any) -> str:
    return 'sha256:' + hashlib.sha256(canonical_json(value)).hexdigest()

def content_digest(record: dict) -> str:
    return digest({k: v for k, v in record.items() if k != 'integrity'})

def proof_object_digest(proof: dict) -> str:
    return digest(proof)

def diagnostic(rule_id: str, code: str, path: str, disposition: str) -> dict:
    return {'rule_id': rule_id, 'code': code, 'path': path, 'disposition': disposition}
