"""Pure validation of restricted WP02 byte transport, never a native client.

Parsing validates supplied bytes/structure only. A valid receipt, digest or
reported match cannot grant authority, verify its source or release a controller
barrier. This module never launches PHP, connects to a database or writes files.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
from typing import Any

from .native_contract import NativeReadReceipt
from .primitives import (
    ContractError, decode_json_object, require_digest, require_identifier,
    require_int, require_mapping,
)

TRANSPORT_VERSION = 'wss-native-read-1.1'
MAX_TRANSPORT_BYTES = 8 * 1024 * 1024
MAX_BLOB_BYTES = 256 * 1024
MAX_BLOB_TOTAL = 4 * 1024 * 1024
MAX_BLOBS = 128
_EVIDENCE_CLASSES = {'REPORTED_NATIVE_READ', 'SYNTHETIC_OFFLINE_FIXTURE'}


@dataclass(frozen=True, slots=True)
class NativeBlob:
    ref: str
    sha256: str
    content: bytes = field(repr=False)

    def __post_init__(self) -> None:
        require_identifier(self.ref, 'blob.ref')
        require_digest(self.sha256, 'blob.sha256')
        if type(self.content) is not bytes or len(self.content) > MAX_BLOB_BYTES:
            raise ContractError('blob.content: bounded immutable bytes required')
        actual = hashlib.sha256(self.content).hexdigest()
        if self.sha256 != 'sha256:' + actual or self.ref != 'blob:' + actual:
            raise ContractError('blob: byte digest/address mismatch')

    @property
    def byte_length(self) -> int:
        return len(self.content)


@dataclass(frozen=True, slots=True)
class NativeReadTransport:
    receipt: NativeReadReceipt
    blobs: tuple[NativeBlob, ...]
    evidence_class: str

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, NativeReadReceipt):
            raise ContractError('transport.receipt: NativeReadReceipt required')
        if type(self.evidence_class) is not str or self.evidence_class not in _EVIDENCE_CLASSES:
            raise ContractError('transport.evidence_class: unsupported class')
        if type(self.blobs) is not tuple or len(self.blobs) > MAX_BLOBS:
            raise ContractError('transport.blobs: bounded tuple required')
        if any(not isinstance(blob, NativeBlob) for blob in self.blobs):
            raise ContractError('transport.blobs: NativeBlob required')
        refs = {blob.ref: blob for blob in self.blobs}
        if len(refs) != len(self.blobs):
            raise ContractError('transport.blobs: duplicate reference')
        if sum(blob.byte_length for blob in self.blobs) > MAX_BLOB_TOTAL:
            raise ContractError('transport.blobs: total byte limit exceeded')
        # Preserve partial source rows; an absent ref is missing data, whereas a
        # supplied ref must resolve and agree with its paired supplied digest.
        for snapshot in self.receipt.snapshots:
            if snapshot.snapshot_ref is not None and snapshot.snapshot_ref.startswith('blob:'):
                if snapshot.snapshot_ref not in refs:
                    raise ContractError('transport: supplied snapshot metadata reference unresolved')
            for ref_field, digest_field in (
                ('item_text_ref', 'item_digest'),
                ('item_presentation_ref', 'item_presentation_digest'),
                ('value_bytes_ref', 'value_digest'),
            ):
                ref, digest = getattr(snapshot, ref_field), getattr(snapshot, digest_field)
                if ref is None:
                    continue
                blob = refs.get(ref)
                if blob is None:
                    raise ContractError('transport: supplied source-byte reference unresolved')
                if digest is not None and digest != blob.sha256:
                    raise ContractError('transport: source-byte digest disagreement')
        # Unknown operator/provenance refs are not resolved or blessed here.

    @classmethod
    def from_json(cls, raw: str | bytes) -> NativeReadTransport:
        if type(raw) is bytes:
            size = len(raw)
        elif type(raw) is str:
            try:
                size = len(raw.encode('utf-8', errors='strict'))
            except UnicodeError:
                raise ContractError('transport: invalid Unicode') from None
        else:
            raise ContractError('transport: raw UTF8 string/bytes required')
        if size > MAX_TRANSPORT_BYTES:
            raise ContractError('transport: byte limit exceeded')
        row = require_mapping(
            decode_json_object(raw, 'transport'), 'transport',
            required=('transport_version', 'evidence_class', 'receipt', 'blobs'),
        )
        if row['transport_version'] != TRANSPORT_VERSION:
            raise ContractError('transport.transport_version: unsupported version')
        raw_blobs = row['blobs']
        if type(raw_blobs) is not list or len(raw_blobs) > MAX_BLOBS:
            raise ContractError('transport.blobs: bounded array required')
        blobs = []
        total = 0
        for value in raw_blobs:
            item = require_mapping(value, 'blob', required=('ref', 'sha256', 'byte_length', 'data_base64'))
            declared = require_int(item['byte_length'], 'blob.byte_length')
            encoded = item['data_base64']
            if declared > MAX_BLOB_BYTES or type(encoded) is not str:
                raise ContractError('blob: unsupported length or encoding type')
            if len(encoded) > 4 * ((MAX_BLOB_BYTES + 2) // 3):
                raise ContractError('blob: base64 size limit exceeded')
            try:
                content = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                raise ContractError('blob: invalid base64') from None
            if base64.b64encode(content).decode('ascii') != encoded or len(content) != declared:
                raise ContractError('blob: noncanonical base64 or length mismatch')
            total += len(content)
            if total > MAX_BLOB_TOTAL:
                raise ContractError('transport.blobs: total byte limit exceeded')
            blobs.append(NativeBlob(item['ref'], item['sha256'], content))
        return cls(NativeReadReceipt.from_mapping(row['receipt']), tuple(blobs), row['evidence_class'])

    def to_mapping(self) -> dict[str, Any]:
        return {
            'transport_version': TRANSPORT_VERSION, 'evidence_class': self.evidence_class,
            'receipt': self.receipt.to_mapping(),
            'blobs': [
                {'ref': blob.ref, 'sha256': blob.sha256, 'byte_length': blob.byte_length,
                 'data_base64': base64.b64encode(blob.content).decode('ascii')}
                for blob in self.blobs
            ],
        }
