"""Explicit local append-only storage for WP01 reference histories.

All filesystem operations happen in explicit calls.  No ledger or snapshot is
created on import.  This is POSIX/cooperative-writer storage, not WORM storage,
an authority service, native-use attestation, or CPC publication/signing code.
Its functions have not been executed or tested in the authoring-only stage.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .native_contract import LedgerRecord
from .primitives import (
    ContractError,
    canonical_json_bytes,
    decode_json_object,
    freeze_json,
    optional_identifier,
    require_digest,
    require_identifier,
    require_int,
    require_mapping,
    require_rfc3339,
)


LEDGER_FORMAT = "wss-ledger-v1"
SNAPSHOT_FORMAT = "wss-snapshot-store-v1"
MAX_ENTRY_BYTES = 4 * 1024 * 1024
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 10_000
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class LedgerError(RuntimeError):
    """Workflow storage failure, not a CPC disposition."""


class LedgerCorruptionError(LedgerError):
    """Existing bytes are invalid; do not truncate, repair, or skip them."""


class DuplicateRecordReference(LedgerError):
    """The caller must retain a distinct receipt, not overwrite a record."""


class LedgerCapacityError(LedgerError):
    """An explicit finite storage bound was exceeded; no silent truncation."""


class SnapshotExistsError(LedgerError):
    """Snapshot references are exclusive, including identical-byte retries."""


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _real_directory(path: str | Path, *, exists: bool) -> Path:
    supplied = Path(path)
    if ".." in supplied.parts:
        raise LedgerError("storage path must not contain parent traversal")
    candidate = supplied.absolute()
    # Refuse symlink ancestors as well as a symlink leaf.  This is a local
    # guard, not protection from a malicious process changing directories.
    for part in (candidate, *candidate.parents):
        if part.is_symlink():
            raise LedgerError("storage directory must not use symlinks")
    if exists:
        if not candidate.is_dir():
            raise LedgerError("storage directory is absent or not a directory")
    elif candidate.exists() or not candidate.parent.is_dir():
        raise LedgerError("new storage needs an existing parent and an unused leaf")
    return candidate


def _checked_fd(path: Path, flags: int, mode: int = 0o600) -> int:
    descriptor = os.open(path, flags | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0), mode)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(descriptor)
        raise LedgerError("storage file must be a regular, non-hardlinked file")
    return descriptor


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        count = os.write(descriptor, raw[offset:])
        if count <= 0:
            raise OSError("short storage write")
        offset += count


def _new_file(path: Path, raw: bytes) -> None:
    descriptor = _checked_fd(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_file(path: Path, maximum: int) -> bytes:
    descriptor = _checked_fd(path, os.O_RDONLY)
    try:
        if os.fstat(descriptor).st_size > maximum:
            raise LedgerCapacityError("existing storage exceeds the supported bound")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise LedgerCapacityError("storage grew beyond the supported bound")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class LedgerScope:
    ledger_ref: str
    run_ref: str
    purpose: str
    source_epoch_ref: str | None = None

    def __post_init__(self) -> None:
        require_identifier(self.ledger_ref, "scope.ledger_ref")
        require_identifier(self.run_ref, "scope.run_ref")
        require_identifier(self.purpose, "scope.purpose")
        optional_identifier(self.source_epoch_ref, "scope.source_epoch_ref")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "ledger_ref": self.ledger_ref,
            "run_ref": self.run_ref,
            "purpose": self.purpose,
            "source_epoch_ref": self.source_epoch_ref,
        }

    def metadata(self) -> dict[str, Any]:
        return {
            "format": LEDGER_FORMAT,
            "scope": self.to_mapping(),
            "scope_is_a_declaration_not_authority": True,
            "encoding": "wss-workflow-json-v1",
        }


class AppendOnlyLedger:
    """Hash-linked local history with unique record refs in one ledger.

    Native entity refs may repeat deliberately.  Uniqueness of a workflow
    record ref does not prove native-event uniqueness, exactly-once delivery,
    authority, source truth, or protected publication.  Only cooperating
    writers honor the POSIX lock.  A torn/corrupt journal stops further use.
    """

    def __init__(self, directory: Path, scope: LedgerScope) -> None:
        # Constructor is a handle only.  create/open perform explicit IO.
        self._directory = directory
        self._scope = scope
        self._metadata_bytes = canonical_json_bytes(scope.metadata()) + b"\n"

    @classmethod
    def create(cls, directory: str | Path, scope: LedgerScope) -> AppendOnlyLedger:
        if not isinstance(scope, LedgerScope):
            raise ContractError("scope: expected LedgerScope")
        target = _real_directory(directory, exists=False)
        handle = cls(target, scope)
        target.mkdir(mode=0o700, exist_ok=False)
        # Failures leave the incomplete directory intact for inspection.
        # There is no automatic rollback or overwrite/retry protocol.
        _new_file(target / "ledger.meta.json", handle._metadata_bytes)
        _new_file(target / ".ledger.lock", b"")
        _new_file(target / "entries.jsonl", b"")
        _fsync_directory(target)
        _fsync_directory(target.parent)
        return handle

    @classmethod
    def open_existing(
        cls, directory: str | Path, expected_scope: LedgerScope
    ) -> AppendOnlyLedger:
        if not isinstance(expected_scope, LedgerScope):
            raise ContractError("scope: expected independently supplied LedgerScope")
        handle = cls(_real_directory(directory, exists=True), expected_scope)
        # Validation is explicit; no files are created or fixed on opening.
        with handle._locked(exclusive=False):
            handle._load_entries_unlocked()
        return handle

    @property
    def directory(self) -> Path:
        return self._directory

    @property
    def scope(self) -> LedgerScope:
        return self._scope

    @contextmanager
    def _locked(self, *, exclusive: bool) -> Iterator[None]:
        _real_directory(self._directory, exists=True)
        descriptor = _checked_fd(self._directory / ".ledger.lock", os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _load_entries_unlocked(self) -> list[dict[str, Any]]:
        metadata = _read_file(self._directory / "ledger.meta.json", MAX_ENTRY_BYTES)
        if metadata != self._metadata_bytes:
            raise LedgerCorruptionError("ledger metadata differs from expected scope")
        raw = _read_file(self._directory / "entries.jsonl", MAX_JOURNAL_BYTES)
        if raw and not raw.endswith(b"\n"):
            raise LedgerCorruptionError("journal has an incomplete trailing record")
        rows: list[dict[str, Any]] = []
        previous = _sha(metadata)
        seen: set[str] = set()
        for line in raw.splitlines(keepends=True):
            if len(rows) >= MAX_RECORDS or len(line) > MAX_ENTRY_BYTES:
                raise LedgerCapacityError("journal exceeds supported record bounds")
            try:
                entry = require_mapping(
                    decode_json_object(line),
                    "entry",
                    required=(
                        "format", "sequence", "previous_digest", "recorded_at",
                        "record", "content_digest",
                    ),
                )
                if entry["format"] != LEDGER_FORMAT:
                    raise ContractError("entry.format: unsupported format")
                require_int(entry["sequence"], "entry.sequence", minimum=1)
                require_rfc3339(entry["recorded_at"], "entry.recorded_at")
                require_digest(entry["previous_digest"], "entry.previous_digest")
                require_digest(entry["content_digest"], "entry.content_digest")
                if entry["sequence"] != len(rows) + 1 or entry["previous_digest"] != previous:
                    raise ContractError("entry: broken sequence or predecessor")
                record = LedgerRecord.from_mapping(entry["record"])
                if record.record_ref in seen:
                    raise ContractError("entry: duplicate workflow record reference")
                body = {key: value for key, value in entry.items() if key != "content_digest"}
                if _sha(canonical_json_bytes(body)) != entry["content_digest"]:
                    raise ContractError("entry: content digest mismatch")
                if canonical_json_bytes(entry) + b"\n" != line:
                    raise ContractError("entry: noncanonical journal record")
            except (ContractError, KeyError, TypeError, ValueError) as exc:
                raise LedgerCorruptionError("journal record failed structural/integrity checks") from exc
            seen.add(record.record_ref)
            previous = entry["content_digest"]
            rows.append(entry)
        return rows

    def read_entries(self) -> tuple[Mapping[str, Any], ...]:
        with self._locked(exclusive=False):
            return tuple(freeze_json(row) for row in self._load_entries_unlocked())

    def read_records(self) -> tuple[LedgerRecord, ...]:
        return tuple(LedgerRecord.from_mapping(row["record"]) for row in self.read_entries())

    def append(self, record: LedgerRecord) -> Mapping[str, Any]:
        if not isinstance(record, LedgerRecord):
            raise ContractError("record: expected typed LedgerRecord")
        # Reparse the serialization before any mutation, so a malformed caller
        # object cannot silently bypass the schema of the stored record.
        checked = LedgerRecord.from_mapping(record.to_mapping())
        with self._locked(exclusive=True):
            rows = self._load_entries_unlocked()
            if any(row["record"]["record_ref"] == checked.record_ref for row in rows):
                raise DuplicateRecordReference("workflow record reference already exists")
            if len(rows) >= MAX_RECORDS:
                raise LedgerCapacityError("ledger record limit reached")
            previous = rows[-1]["content_digest"] if rows else _sha(self._metadata_bytes)
            entry: dict[str, Any] = {
                "format": LEDGER_FORMAT,
                "sequence": len(rows) + 1,
                "previous_digest": previous,
                "recorded_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                "record": checked.to_mapping(),
            }
            entry["content_digest"] = _sha(canonical_json_bytes(entry))
            raw = canonical_json_bytes(entry) + b"\n"
            if len(raw) > MAX_ENTRY_BYTES:
                raise LedgerCapacityError("record exceeds workflow entry bound")
            descriptor = _checked_fd(self._directory / "entries.jsonl", os.O_WRONLY | os.O_APPEND)
            try:
                if os.fstat(descriptor).st_size + len(raw) > MAX_JOURNAL_BYTES:
                    raise LedgerCapacityError("journal byte limit reached")
                # A failed/partial append is not truncated or silently retried.
                _write_all(descriptor, raw)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return freeze_json(entry)


@dataclass(frozen=True, slots=True)
class SnapshotReference:
    store_ref: str
    snapshot_ref: str
    sha256: str
    byte_length: int

    def __post_init__(self) -> None:
        require_identifier(self.store_ref, "snapshot.store_ref")
        require_identifier(self.snapshot_ref, "snapshot.snapshot_ref")
        require_digest(self.sha256, "snapshot.sha256")
        require_int(self.byte_length, "snapshot.byte_length")
        if self.byte_length > MAX_SNAPSHOT_BYTES:
            raise LedgerCapacityError("snapshot exceeds supported byte bound")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "store_ref": self.store_ref, "snapshot_ref": self.snapshot_ref,
            "sha256": self.sha256, "byte_length": self.byte_length,
        }

    @classmethod
    def from_mapping(cls, data: object) -> SnapshotReference:
        row = require_mapping(
            data, "snapshot", required=("store_ref", "snapshot_ref", "sha256", "byte_length")
        )
        return cls(**row)


class SnapshotStore:
    """Explicit immutable-name local byte storage; no native truth inference.

    Snapshot creation and ledger append are separate operations, not a shared
    filesystem transaction.  A failure can leave an orphan file; retain it and
    report incomplete accounting instead of silently deleting or overwriting.
    """

    def __init__(self, directory: Path, store_ref: str) -> None:
        self._directory = directory
        self._store_ref = require_identifier(store_ref, "store_ref")
        self._metadata_bytes = canonical_json_bytes(
            {"format": SNAPSHOT_FORMAT, "store_ref": self._store_ref}
        ) + b"\n"

    @classmethod
    def create(cls, directory: str | Path, store_ref: str) -> SnapshotStore:
        target = _real_directory(directory, exists=False)
        handle = cls(target, store_ref)
        target.mkdir(mode=0o700, exist_ok=False)
        _new_file(target / "snapshot-store.meta.json", handle._metadata_bytes)
        _fsync_directory(target)
        _fsync_directory(target.parent)
        return handle

    @classmethod
    def open_existing(cls, directory: str | Path, expected_store_ref: str) -> SnapshotStore:
        handle = cls(_real_directory(directory, exists=True), expected_store_ref)
        handle._check_metadata()
        return handle

    def _check_metadata(self) -> None:
        _real_directory(self._directory, exists=True)
        if _read_file(self._directory / "snapshot-store.meta.json", MAX_ENTRY_BYTES) != self._metadata_bytes:
            raise LedgerCorruptionError("snapshot store metadata differs from expected store")

    def _path(self, snapshot_ref: str) -> Path:
        # Opaque refs cannot select arbitrary paths.  This filename hash is
        # storage addressing only, never a native occurrence or content proof.
        token = require_identifier(snapshot_ref, "snapshot_ref")
        return self._directory / (hashlib.sha256(token.encode("utf-8")).hexdigest() + ".bin")

    def put(self, snapshot_ref: str, content: bytes) -> SnapshotReference:
        if type(content) is not bytes:
            raise ContractError("snapshot content: expected immutable bytes")
        if len(content) > MAX_SNAPSHOT_BYTES:
            raise LedgerCapacityError("snapshot exceeds supported byte bound")
        self._check_metadata()
        target = self._path(snapshot_ref)
        reference = SnapshotReference(self._store_ref, snapshot_ref, _sha(content), len(content))
        try:
            _new_file(target, content)
        except FileExistsError as exc:
            raise SnapshotExistsError("snapshot reference already exists; no overwrite") from exc
        _fsync_directory(self._directory)
        return reference

    def get(self, reference: SnapshotReference) -> bytes:
        if not isinstance(reference, SnapshotReference) or reference.store_ref != self._store_ref:
            raise ContractError("snapshot reference belongs to a different store")
        self._check_metadata()
        raw = _read_file(self._path(reference.snapshot_ref), MAX_SNAPSHOT_BYTES)
        if len(raw) != reference.byte_length or _sha(raw) != reference.sha256:
            raise LedgerCorruptionError("snapshot bytes differ from supplied reference")
        return raw
