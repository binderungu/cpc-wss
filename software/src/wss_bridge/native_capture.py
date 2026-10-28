"""Explicit local preservation of supplied WP02 transport, never a native reader.

Capture coherence is not truth, authorization, or mitigation of a lying producer.
Import is inert. All writes/readback occur only in the three explicit APIs below.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any

from .ledger import SnapshotExistsError, SnapshotReference, SnapshotStore
from .native_contract import NativeReadStatus
from .native_transport import NativeReadTransport
from .primitives import (
    ContractError, canonical_json_bytes, decode_json_object, require_int,
    require_mapping,
)

CAPTURE_FORMAT = "wss-native-capture-v2"
_MANIFEST_KEYS = ("format", "raw_reference", "blob_references", "metadata_issues")


@dataclass(frozen=True, slots=True)
class CaptureBundle:
    transport: NativeReadTransport
    raw_reference: SnapshotReference
    blob_references: tuple[SnapshotReference, ...]
    manifest_reference: SnapshotReference
    metadata_issues: tuple[str, ...]


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _expected(store: SnapshotStore, name: str, raw: bytes) -> SnapshotReference:
    if not isinstance(store, SnapshotStore):
        raise ContractError("capture.store: SnapshotStore required")
    # WP01 has no public store identity accessor. Keep this narrow, documented
    # coupling rather than modifying the preserved WP01 storage contract.
    return SnapshotReference(store._store_ref, name, "sha256:" + _digest(raw), len(raw))


def _store_exact(store: SnapshotStore, name: str, raw: bytes) -> SnapshotReference:
    expected = _expected(store, name, raw)
    try:
        actual = store.put(name, raw)
    except SnapshotExistsError:
        # Existing names are never overwritten; mismatched/unreadable bytes fail.
        actual = expected
    if actual != expected or store.get(actual) != raw:
        raise ContractError("capture: storage readback differs from supplied bytes")
    return actual


def persist_raw(raw: bytes, store: SnapshotStore) -> SnapshotReference:
    """Preserve even invalid transport bytes before any parse/semantic checks.

    WP01's finite snapshot bound still applies. Reuse is verified byte-for-byte;
    no attempt, occurrence, publication or authority identity is derived here.
    """
    if type(raw) is not bytes:
        raise ContractError("capture.raw: immutable bytes required")
    return _store_exact(store, "capture-raw:" + _digest(raw), raw)


def _source_bytes(ref: object, blobs: dict[str, bytes]) -> bytes:
    if type(ref) is not str or ref not in blobs:
        raise ContractError("capture.metadata: source bytes absent")
    return blobs[ref]


def _text(ref: object, blobs: dict[str, bytes], expected: object) -> None:
    try:
        text = _source_bytes(ref, blobs).decode("utf-8", errors="strict")
    except UnicodeError:
        raise ContractError("capture.metadata: invalid source text") from None
    if type(expected) is not str or not text or text != expected:
        raise ContractError("capture.metadata: source text disagreement")


def _equal(actual: object, expected: object) -> None:
    # Canonical equality preserves bool/int distinctions that Python == ignores.
    if canonical_json_bytes(actual) != canonical_json_bytes(expected):
        raise ContractError("capture.metadata: source projection disagreement")


def _source_metadata_int(value: object) -> int:
    """Match bounded canonical PDO integer strings without coercing typed records."""
    if type(value) is str and re.fullmatch(r"(?:0|[1-9][0-9]*)", value) and len(value) <= 19:
        value = int(value)
    if type(value) is not int or value < 0 or value > 9223372036854775807:
        raise ContractError("capture.metadata: source integer unavailable")
    return value


def _target_window_metadata(transport: NativeReadTransport) -> None:
    receipt = transport.receipt
    # The new category fact must agree with retained source-window metadata.
    # This is local coherence only, never independent source authentication.
    decoded = []
    for blob in transport.blobs:
        try:
            decoded.append(decode_json_object(blob.content))
        except ContractError:
            continue
    for window in (receipt.target_window_before_ref, receipt.target_window_after_ref):
        candidates = [row for row in decoded if row.get("target_window_ref") == window]
        if window is None or len(candidates) != 1:
            raise ContractError("capture.metadata: target window cardinality")
        window_meta = require_mapping(candidates[0], "target-window", required=("target_window_ref", "native_target_rows"))
        rows = window_meta["native_target_rows"]
        if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
            raise ContractError("capture.metadata: target row cardinality")
        if receipt.target is None:
            raise ContractError("capture.metadata: target unavailable")
        for field in ("courseid", "cmid"):
            observed = _source_metadata_int(rows[0].get(field))
            require_int(observed, "metadata." + field, minimum=1)
            _equal(observed, getattr(receipt.target, field))
        category = _source_metadata_int(rows[0].get("course_category"))
        # PDO may return a canonical numeric string: match PHP source_int,
        # keeping operator/typed-receipt integers strictly typed elsewhere.
        if category <= 0:
            raise ContractError("capture.metadata: ordinary course not established")
        _equal(category, receipt.target_course_category)


def _singleton_metadata(transport: NativeReadTransport) -> None:
    receipt = transport.receipt
    event = receipt.occurrences[0].to_mapping()
    snapshot = receipt.snapshots[0].to_mapping()
    blobs = {blob.ref: blob.content for blob in transport.blobs}
    meta = require_mapping(
        decode_json_object(_source_bytes(snapshot["snapshot_ref"], blobs)),
        "snapshot-metadata", required=("standard_log_record_id", "raw_other_ref",
                                       "native_snapshot_fields", "source_projection_details"),
    )
    require_int(meta["standard_log_record_id"], "metadata.logid", minimum=1)
    _equal(meta["standard_log_record_id"], event["standard_log_record_id"])
    snapshot["snapshot_ref"] = None
    _equal(meta["native_snapshot_fields"], snapshot)
    raw_other = _source_bytes(meta["raw_other_ref"], blobs)
    details = require_mapping(
        meta["source_projection_details"], "source-projection-details",
        required=("tmp_completed", "raw_item_type_ref", "item_byte_length",
                  "presentation_byte_length", "value_byte_length"),
    )
    if require_int(details["tmp_completed"], "tmp_completed") != 0:
        raise ContractError("capture.metadata: temporary value row")
    _text(details["raw_item_type_ref"], blobs, snapshot["item_type"])
    for length_field, ref_field in (
        ("item_byte_length", "item_text_ref"),
        ("presentation_byte_length", "item_presentation_ref"),
        ("value_byte_length", "value_bytes_ref"),
    ):
        declared = require_int(details[length_field], length_field)
        if declared != len(_source_bytes(snapshot[ref_field], blobs)):
            raise ContractError("capture.metadata: source length disagreement")

    event_candidates = []
    for blob in transport.blobs:
        try:
            candidate = decode_json_object(blob.content)
        except ContractError:
            continue
        if "native_occurrence" in candidate:
            event_candidates.append(candidate)
    if len(event_candidates) != 1:
        raise ContractError("capture.metadata: event metadata cardinality")
    event_meta = require_mapping(
        event_candidates[0], "event-metadata", required=("native_occurrence",
        "raw_other_ref", "raw_text_column_refs", "raw_other_byte_length"),
    )
    _equal(event_meta["native_occurrence"], event)
    _equal(event_meta["raw_other_ref"], meta["raw_other_ref"])
    if require_int(event_meta["raw_other_byte_length"], "raw_other_byte_length") != len(raw_other):
        raise ContractError("capture.metadata: other byte length disagreement")
    text_refs = require_mapping(event_meta["raw_text_column_refs"], "raw-text-refs",
                                required=("eventname", "objecttable", "origin"))
    for key, ref in text_refs.items():
        _text(ref, blobs, event[key])


def _issues(transport: NativeReadTransport) -> tuple[str, ...]:
    receipt = transport.receipt
    issues = []
    if receipt.status is not NativeReadStatus.MATCH_OBSERVED:
        issues.append("CAPTURE_STATUS_NOT_MATCH")
    if len(receipt.occurrences) != 1:
        issues.append("CAPTURE_OCCURRENCE_NOT_SINGLETON")
    if len(receipt.snapshots) != 1:
        issues.append("CAPTURE_SNAPSHOT_NOT_SINGLETON")
    try:
        _target_window_metadata(transport)
    except ContractError:
        issues.append("CAPTURE_METADATA_INCOHERENT")
    if len(receipt.occurrences) == len(receipt.snapshots) == 1:
        try:
            _singleton_metadata(transport)
        except ContractError:
            if "CAPTURE_METADATA_INCOHERENT" not in issues:
                issues.append("CAPTURE_METADATA_INCOHERENT")
    return tuple(issues)


def _manifest(raw_reference: SnapshotReference, references: tuple[SnapshotReference, ...],
              issues: tuple[str, ...]) -> dict[str, Any]:
    return {"format": CAPTURE_FORMAT, "raw_reference": raw_reference.to_mapping(),
            "blob_references": [item.to_mapping() for item in references],
            "metadata_issues": list(issues)}


def _raw(raw_reference: SnapshotReference, store: SnapshotStore) -> bytes:
    raw = store.get(raw_reference)
    if raw_reference != _expected(store, "capture-raw:" + _digest(raw), raw):
        raise ContractError("capture.raw_reference: unsupported storage address")
    return raw


def check_and_store_capture(raw_reference: SnapshotReference, store: SnapshotStore) -> CaptureBundle:
    """Store every validly decoded blob and closed manifest, then readback all.

    Invalid transport raises after raw preservation. Semantic failures produce
    issue flags with all decoded bytes retained; they never grant an anchor.
    Partial writes remain inspectable orphans. Caller owns cooperative locking.
    """
    transport = NativeReadTransport.from_json(_raw(raw_reference, store))
    references = tuple(_store_exact(store, blob.ref, blob.content) for blob in transport.blobs)
    issues = _issues(transport)
    manifest_raw = canonical_json_bytes(_manifest(raw_reference, references, issues))
    manifest_reference = _store_exact(store, "capture-manifest:" + _digest(manifest_raw), manifest_raw)
    # The read-only path verifies the entire closure again before returning.
    return load_capture(manifest_reference, store)


def load_capture(manifest_reference: SnapshotReference, store: SnapshotStore) -> CaptureBundle:
    """Read-only replay, validating complete manifest/transport/blob linkage."""
    raw_manifest = store.get(manifest_reference)
    if manifest_reference != _expected(store, "capture-manifest:" + _digest(raw_manifest), raw_manifest):
        raise ContractError("capture.manifest_reference: unsupported storage address")
    row = require_mapping(decode_json_object(raw_manifest), "capture-manifest", required=_MANIFEST_KEYS)
    if row["format"] != CAPTURE_FORMAT:
        raise ContractError("capture.manifest: unsupported format")
    raw_reference = SnapshotReference.from_mapping(row["raw_reference"])
    transport = NativeReadTransport.from_json(_raw(raw_reference, store))
    supplied = row["blob_references"]
    if type(supplied) is not list or len(supplied) != len(transport.blobs):
        raise ContractError("capture.manifest: blob reference cardinality")
    references = tuple(SnapshotReference.from_mapping(item) for item in supplied)
    for blob, reference in zip(transport.blobs, references):
        if reference != _expected(store, blob.ref, blob.content) or store.get(reference) != blob.content:
            raise ContractError("capture.manifest: blob reference/bytes disagreement")
    issues = _issues(transport)
    if canonical_json_bytes(_manifest(raw_reference, references, issues)) != raw_manifest:
        raise ContractError("capture.manifest: noncanonical or inconsistent manifest")
    return CaptureBundle(transport, raw_reference, references, manifest_reference, issues)
