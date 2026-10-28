"""Explicit WP06 admission/export orchestration, never a new CPC validator.

All writes are local and explicit. No native/producer/outcome runner on import or
evaluation. Cooperative POSIX storage; no writable recovery or atomic batch claim.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import MappingProxyType
from typing import Any, Mapping
import uuid

from .configuration import verify_pinned_references
from .ledger import (AppendOnlyLedger, LedgerScope, SnapshotReference, SnapshotStore,
    LedgerCorruptionError, _real_directory, _new_file, _fsync_directory, _checked_fd, _read_file)
from .native_contract import LedgerRecord, RecordKind
from .primitives import (ContractError, canonical_json_bytes, decode_json_object,
                         freeze_json, plain_json, require_identifier)

FORMAT = "wss-cpc-adapter-v1"
_PACKAGE = "_wss_wp06_pinned_cpc2"
_MODULES = ("common", "schema", "integrity", "profile", "validator", "api", "export")


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _ref(prefix: str) -> str:
    return prefix + ":" + uuid.uuid4().hex


def _dependency(name: str):
    """Execute only the verified bundled origin, without sys.path/pyc lookup."""
    refs = Path(__file__).resolve().parents[2] / "references"
    origin = refs / "cpc_release/implementation/src/cpc2"
    if name not in _MODULES:
        raise ContractError("unsupported CPC dependency")
    for key, module in tuple(sys.modules.items()):
        if key == _PACKAGE or key.startswith(_PACKAGE + "."):
            if not getattr(module, "__file__", None) or not Path(module.__file__).resolve().is_relative_to(origin):
                raise ContractError("untrusted CPC module origin")
    for part in ("__init__", *_MODULES):
        fullname = _PACKAGE if part == "__init__" else _PACKAGE + "." + part
        if fullname in sys.modules:
            continue
        verify_pinned_references(refs)
        path = origin / (part + ".py")
        spec = importlib.util.spec_from_file_location(fullname, path,
            submodule_search_locations=[str(origin)] if part == "__init__" else None)
        module = importlib.util.module_from_spec(spec)
        sys.modules[fullname] = module
        try:
            exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
        except Exception:
            del sys.modules[fullname]
            raise
    return sys.modules[_PACKAGE + "." + name]


def _keys(value: Any, depth: int = 0, *, plain: bool = False, fingerprint: bool = False, budget=None):
    budget = [1048576] if budget is None else budget
    budget[0] -= 1
    if budget[0] < 0:
        raise ContractError("operator keys exceed aggregate bound")
    if depth > 32:
        raise ContractError("operator keys: depth/cycle bound")
    if isinstance(value, Mapping):
        if any(type(k) is not str for k in value):
            raise ContractError("operator keys: string keys required")
        if any(len(k) > 1048576 for k in value):
            raise ContractError("operator key identifier exceeds bound")
        budget[0] -= sum(len(k.encode('utf-8', errors='surrogatepass')) for k in value)
        if budget[0] < 0:
            raise ContractError("operator keys exceed aggregate bound")
        row = {k: _keys(v, depth + 1, plain=plain, fingerprint=fingerprint, budget=budget) for k, v in value.items()}
        if fingerprint:
            return {"type": "mapping", "sha256": _sha(canonical_json_bytes(row))}
        return row if plain or fingerprint else MappingProxyType(row)
    if type(value) in (tuple, list):
        row = [_keys(v, depth + 1, plain=plain, fingerprint=fingerprint, budget=budget) for v in value]
        if fingerprint:
            return {"type": "array", "sha256": _sha(canonical_json_bytes(row))}
        return row if plain or fingerprint else tuple(row)
    if type(value) in (bytes, str):
        if len(value) > 1048576:
            raise ContractError("operator key material exceeds bound")
        raw = value if type(value) is bytes else value.encode("utf-8", errors="surrogatepass")
        budget[0] -= len(raw)
        if budget[0] < 0:
            raise ContractError("operator key material exceeds bound")
        return {"type": type(value).__name__, "sha256": _sha(raw)} if fingerprint else value
    if value is None or type(value) in (bool, int):
        return {"type": type(value).__name__, "sha256": _sha(canonical_json_bytes(value))} if fingerprint else value
    raise ContractError("operator keys: unsupported value type")


@dataclass(frozen=True, slots=True)
class AdmissionContext:
    """Supplied operator assertions, not approval or a chain-derived trust root.

    Structurally invalid supported JSON configurations deliberately reach the
    actual API and its ERROR_CONFIG path. Key bytes stay in memory; receipts store
    only typed key fingerprints. Context transport uses the workflow JSON domain.
    """
    profile: Any = field(repr=False)
    key_registry: Any = field(repr=False)
    validation_time: Any
    receipt: Mapping = field(init=False, repr=False)
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        profile, now = freeze_json(self.profile), freeze_json(self.validation_time)
        keys = _keys(self.key_registry)
        receipt = {"format": "wss-cpc-context-v1", "profile": profile,
                   "validation_time": now, "key_fingerprints_not_material": _keys(keys, fingerprint=True)}
        raw = canonical_json_bytes(receipt)
        if len(raw) > 1048576:
            raise ContractError("operator context exceeds supported bound")
        object.__setattr__(self, "profile", profile)
        object.__setattr__(self, "validation_time", now)
        object.__setattr__(self, "key_registry", keys)
        object.__setattr__(self, "receipt", freeze_json(receipt))
        object.__setattr__(self, "digest", _sha(raw))

    def arguments(self) -> tuple:
        return plain_json(self.profile), _keys(self.key_registry, plain=True), plain_json(self.validation_time)


@dataclass(frozen=True, slots=True)
class EvaluationReceipt:
    receipt_ref: str
    input_ref: str | None
    status: str
    result: Mapping | None
    failure_code: str | None


class AdapterStopped(ContractError):
    """Local orchestration refusal, never a core disposition."""


def _transport(raw: Any) -> tuple[bytes, str]:
    if type(raw) is bytes:
        return raw, "BYTES"
    if type(raw) is str:
        if len(raw) > 16777216:
            raise ContractError("raw string exceeds snapshot retention bound")
        try:
            return raw.encode("utf-8"), "STR_UTF8"
        except UnicodeEncodeError:
            return raw.encode("utf-8", errors="surrogatepass"), "STR_SURROGATEPASS_NOT_VALID_UTF8"
    return canonical_json_bytes(raw), "NON_TRANSPORT_JSON_API_MISUSE"


class CPCAdapter:
    """One frozen-context batch, retained input receipts, no writable reopen."""
    def __init__(self, root, context, run_ref, journal, store, *, writable):
        self.root, self.context, self.run_ref = root, context, run_ref
        self.journal, self.store = journal, store
        self._writable, self._poisoned = writable, False
        self._metadata = canonical_json_bytes({"format": FORMAT, "run_ref": run_ref,
            "context_digest": context.digest, "ledger_scope": journal.scope.to_mapping(),
            "store_ref": store._store_ref})

    @classmethod
    def create(cls, root: str | Path, context: AdmissionContext, run_ref: str) -> CPCAdapter:
        if type(context) is not AdmissionContext:
            raise ContractError("AdmissionContext required")
        require_identifier(run_ref, "run_ref")
        target = _real_directory(root, exists=False)
        target.mkdir(mode=0o700, exist_ok=False)
        scope = LedgerScope(_ref("admission-ledger"), run_ref, "OFFLINE_CPC_ADMISSION")
        store_ref = _ref("admission-store")
        _new_file(target / "adapter.meta.json", canonical_json_bytes({"format": FORMAT,
            "run_ref": run_ref, "context_digest": context.digest, "ledger_scope": scope.to_mapping(),
            "store_ref": store_ref}))
        _new_file(target / ".adapter.lock", b"")
        journal = AppendOnlyLedger.create(target / "journal", scope)
        store = SnapshotStore.create(target / "snapshots", store_ref)
        handle = cls(target, context, run_ref, journal, store, writable=True)
        context_ref = handle._save("operator-context", canonical_json_bytes(context.receipt))
        handle._append("OPENED", {"context_reference": context_ref.to_mapping()})
        _fsync_directory(target)
        _fsync_directory(target.parent)
        return handle

    @classmethod
    def open_readonly(cls, root, context: AdmissionContext, run_ref: str) -> CPCAdapter:
        if type(context) is not AdmissionContext:
            raise ContractError("AdmissionContext required")
        target = _real_directory(root, exists=True)
        meta = decode_json_object(_read_file(target / "adapter.meta.json", 1048576))
        if (set(meta) != {"format", "run_ref", "context_digest", "ledger_scope", "store_ref"}
                or meta["format"] != FORMAT or meta["run_ref"] != run_ref or meta["context_digest"] != context.digest):
            raise LedgerCorruptionError("adapter expected context/scope mismatch")
        scope = LedgerScope(**meta["ledger_scope"])
        if scope.run_ref != run_ref:
            raise LedgerCorruptionError("adapter scope mismatch")
        handle = cls(target, context, run_ref, AppendOnlyLedger.open_existing(target / "journal", scope),
                     SnapshotStore.open_existing(target / "snapshots", meta["store_ref"]), writable=False)
        handle.view()
        return handle

    @contextmanager
    def _guard(self, *, write: bool):
        descriptor = None
        try:
            if write and (not self._writable or self._poisoned):
                raise AdapterStopped("adapter is readonly or has uncertain writes")
            descriptor = _checked_fd(self.root / ".adapter.lock", 0)
            fcntl.flock(descriptor, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            if _read_file(self.root / "adapter.meta.json", 1048576) != self._metadata:
                raise LedgerCorruptionError("adapter metadata differs from expected context")
            if write and self._poisoned:
                raise AdapterStopped("adapter write uncertainty")
            yield
        except Exception:
            if write:
                self._poisoned = True
            raise
        finally:
            if descriptor is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                import os
                os.close(descriptor)

    def _save(self, prefix: str, raw: bytes) -> SnapshotReference:
        try:
            ref = self.store.put(_ref(prefix), raw)
            if self.store.get(ref) != raw:
                raise LedgerCorruptionError("adapter snapshot readback failed")
            return ref
        except Exception:
            self._poisoned = True
            raise

    def _append(self, event, data):
        ref = _ref("admission-event")
        try:
            self.journal.append(LedgerRecord(ref, RecordKind.AUDIT_REFERENCE, ref,
                {"audit_ref": ref, "status": "RECORDED", "format": FORMAT, "event": event, "data": data}))
        except Exception:
            self._poisoned = True
            raise

    def _state(self) -> dict:
        rows, opened, export_started, exported, failures = {}, False, False, None, []
        for record in self.journal.read_records():
            p = plain_json(record.payload)
            if (record.kind is not RecordKind.AUDIT_REFERENCE or set(p) != {"audit_ref", "status", "format", "event", "data"}
                    or p["format"] != FORMAT):
                raise LedgerCorruptionError("adapter event format mismatch")
            event, data = p["event"], p["data"]
            if event == "OPENED":
                if opened or rows:
                    raise LedgerCorruptionError("duplicate/late context")
                raw = self.store.get(SnapshotReference.from_mapping(data["context_reference"]))
                if raw != canonical_json_bytes(self.context.receipt):
                    raise LedgerCorruptionError("adapter context snapshot mismatch")
                opened = True
            elif event == "RECEIVED":
                if not opened or data["receipt_ref"] in rows:
                    raise LedgerCorruptionError("adapter received identity mismatch")
                rows[data["receipt_ref"]] = {**data, "raw_reference": None, "raw_kind": None,
                    "returned_reference": None, "result": None, "failure_code": None, "stage": "RECEIVED"}
            elif event in {"RAW_CAPTURED", "CORE_RETURNED", "RESULT_RETAINED", "FAILED"}:
                row = rows[data["receipt_ref"]]
                if event == "RAW_CAPTURED":
                    if row["stage"] != "RECEIVED":
                        raise LedgerCorruptionError("raw capture event order")
                    self.store.get(SnapshotReference.from_mapping(data["raw_reference"]))
                    if data.get("requested_ref_reference") is not None:
                        requested = self.store.get(SnapshotReference.from_mapping(data["requested_ref_reference"]))
                        if row["input_ref"] is not None and requested != row["input_ref"].encode("utf-8"):
                            raise LedgerCorruptionError("operator ref snapshot differs from allocated input_ref")
                    row.update(raw_reference=data["raw_reference"], raw_kind=data["raw_kind"], stage="RAW_CAPTURED")
                    row["requested_ref_reference"] = data.get("requested_ref_reference")
                    row["requested_ref_kind"] = data.get("requested_ref_kind")
                elif event == "CORE_RETURNED":
                    if row["stage"] != "RAW_CAPTURED":
                        raise LedgerCorruptionError("core return event order")
                    self.store.get(SnapshotReference.from_mapping(data["returned_reference"]))
                    row["returned_reference"] = data["returned_reference"]
                    row["stage"] = "CORE_RETURNED"
                elif event == "RESULT_RETAINED":
                    if row["stage"] != "CORE_RETURNED":
                        raise LedgerCorruptionError("result event order")
                    result = decode_json_object(self.store.get(SnapshotReference.from_mapping(row["returned_reference"])))
                    if result["input_ref"] != row["input_ref"] or result["input_sha256"] != row["raw_reference"]["sha256"]:
                        raise LedgerCorruptionError("adapter result identity/hash mismatch")
                    row["result"] = result
                    row["stage"] = "RESULT_RETAINED"
                else:
                    if row["stage"] in {"RESULT_RETAINED", "FAILED"}:
                        raise LedgerCorruptionError("failure event order")
                    row["failure_code"] = data["failure_code"]
                    row["stage"] = "FAILED"
                    failures.append(data)
            elif event == "EXPORT_STARTED":
                if export_started:
                    raise LedgerCorruptionError("duplicate export attempt")
                export_started = True
            elif event == "EXPORT_COMPLETED":
                if not export_started or exported is not None:
                    raise LedgerCorruptionError("export event order invalid")
                for file in data["files"]:
                    relative = file["name"]
                    if relative not in {"admitted.jsonl", "exclusion_ledger.jsonl", "accounting.json"}:
                        raise LedgerCorruptionError("export path outside whitelist")
                    if _sha(_read_file(self.root / "export" / relative, 16777216)) != file["sha256"]:
                        raise LedgerCorruptionError("export bytes changed")
                exported = data
            elif event == "EXPORT_FAILED":
                failures.append(data)
            else:
                raise LedgerCorruptionError("unknown adapter event")
        if not opened:
            raise LedgerCorruptionError("adapter context event missing")
        results = [r["result"] for r in rows.values() if r["result"] is not None]
        # Replaying retained decisions must remain possible if a code dependency
        # is now missing. Schema/whitelist validation happened before retention;
        # export revalidates through the pinned partitioner at its own boundary.
        counts = {name: 0 for name in ("ADMIT", "REJECT", "QUARANTINE", "ERROR_INPUT", "NOT_EVALUATED_CONFIG")}
        for result in results:
            status = "NOT_EVALUATED_CONFIG" if result["disposition"] == "ERROR_CONFIG" else result["disposition"]
            if status not in counts:
                raise LedgerCorruptionError("retained disposition unsupported")
            counts[status] += 1
        unresolved = [r["receipt_ref"] for r in rows.values() if r["result"] is None]
        pending_export = export_started and exported is None
        return {"rows": list(rows.values()), "received": len(rows), "results": results,
            "counts": counts, "unresolved_receipts": unresolved, "failures": failures,
            "evaluation_accounting_complete": not unresolved,
            "accounting_complete": not unresolved and not failures and not pending_export,
            "export_started": export_started, "export": exported,
            "status": "INCOMPLETE" if unresolved or failures or pending_export else "EXPORTED" if exported else "OPEN",
            "context_digest": self.context.digest}

    def view(self) -> Mapping:
        with self._guard(write=False):
            return freeze_json(self._state())

    def evaluate(self, raw: Any, *, input_ref: str | None = None) -> EvaluationReceipt:
        receipt_ref = _ref("evaluation")
        result, failure = None, None
        with self._guard(write=True):
            state = self._state()
            if state["status"] == "INCOMPLETE" or state["export_started"]:
                raise AdapterStopped("batch stopped or sealed")
            # Short per-batch refs do not depend on a functioning profile import.
            # They identify local API inputs, never native events or learners.
            if input_ref is None:
                index, used = len(state["rows"]), {r["input_ref"] for r in state["rows"]}
                def token(number):
                    alphabet, encoded = "0123456789abcdefghijklmnopqrstuvwxyz", ""
                    while number >= 36:
                        number, digit = divmod(number, 36)
                        encoded = alphabet[digit] + encoded
                    return alphabet[number] + encoded
                while token(index) in used:
                    index += 1
                ref = token(index)
            else:
                try:
                    ref = require_identifier(input_ref, "input_ref")
                except ContractError:
                    ref = None
            try:
                self._append("RECEIVED", {"receipt_ref": receipt_ref, "input_ref": ref})
                data, kind = _transport(raw)
                raw_ref = self._save("received-raw", data)
                requested_ref = None
                requested_kind = None
                if input_ref is not None:
                    failure = "INVALID_OR_UNPRESERVABLE_OPERATOR_INPUT_REF"
                    requested_bytes, requested_kind = _transport(input_ref)
                    requested_ref = self._save("requested-operator-ref", requested_bytes)
                failure = "RAW_OR_RECEIPT_PRESERVATION_FAILURE"
                self._append("RAW_CAPTURED", {"receipt_ref": receipt_ref, "raw_reference": raw_ref.to_mapping(),
                    "raw_kind": kind, "requested_ref_reference": None if requested_ref is None else requested_ref.to_mapping(),
                    "requested_ref_kind": requested_kind})
                if ref is None:
                    failure = "INVALID_OPERATOR_INPUT_REF"
                    raise AdapterStopped(failure)
                failure = "DEPENDENCY_OR_CONFIGURATION_EVALUATION_FAILURE"
                profile, keys, now = self.context.arguments()
                config_errors = _dependency("profile").validate_profile(profile, now, keys)
                maximum = profile["input_limits"]["max_identifier_chars"] if not config_errors else 256
                if len(ref) > maximum:
                    failure = "AUTOMATIC_REF_CAPACITY_EXHAUSTED" if input_ref is None else "INVALID_OPERATOR_INPUT_REF"
                    raise AdapterStopped(failure)
                if any(row["input_ref"] == ref for row in state["rows"]):
                    failure = "DUPLICATE_OPERATOR_INPUT_REF"
                    raise AdapterStopped(failure)
                failure = "CORE_API_EXCEPTION"
                actual = _dependency("api").validate_raw(raw, profile, keys, now, input_ref=ref)
                failure = "CORE_RESULT_PERSISTENCE_FAILURE"
                returned_ref = self._save("actual-core-return", canonical_json_bytes(actual))
                self._append("CORE_RETURNED", {"receipt_ref": receipt_ref, "returned_reference": returned_ref.to_mapping()})
                failure = "CORE_RESULT_CONTRACT_FAILURE"
                _dependency("export").partition_results([actual])
                if actual["input_ref"] != ref or actual["input_sha256"] != _sha(data):
                    raise ContractError("core returned wrong input identity/hash")
                failure = "RESULT_RETENTION_LEDGER_FAILURE"
                self._append("RESULT_RETAINED", {"receipt_ref": receipt_ref})
                result = freeze_json(actual)
                return EvaluationReceipt(receipt_ref, ref, "RESULT_RETAINED", result, None)
            except Exception as error:
                failure = failure or "RAW_OR_RECEIPT_PRESERVATION_FAILURE"
                if not self._poisoned:
                    self._append("FAILED", {"receipt_ref": receipt_ref, "failure_code": failure,
                        "exception_class": type(error).__name__ if type(error) in {TypeError, ValueError, RuntimeError, ContractError, AdapterStopped} else "UNEXPECTED_EXCEPTION"})
                return EvaluationReceipt(receipt_ref, ref, "UNRESOLVED", None, failure)

    def export(self) -> Mapping:
        with self._guard(write=True):
            state = self._state()
            if state["status"] == "INCOMPLETE" or state["export_started"]:
                raise AdapterStopped("cannot export unresolved or already sealed batch")
            self._append("EXPORT_STARTED", {"received": state["received"]})
            try:
                partition = _dependency("export").partition_results(state["results"])
                target = self.root / "export"
                target.mkdir(mode=0o700, exist_ok=False)
                _fsync_directory(self.root)
                summary = {k: v for k, v in partition.items() if k not in {"admitted", "excluded"}}
                files = {"admitted.jsonl": b"".join(canonical_json_bytes(r) + b"\n" for r in partition["admitted"]),
                    "exclusion_ledger.jsonl": b"".join(canonical_json_bytes(r) + b"\n" for r in partition["excluded"]),
                    "accounting.json": canonical_json_bytes(summary) + b"\n"}
                refs = []
                for name, data in files.items():
                    _new_file(target / name, data)
                    _fsync_directory(target)
                    if _read_file(target / name, 16777216) != data:
                        raise LedgerCorruptionError("export readback mismatch")
                    refs.append({"name": name, "sha256": _sha(data)})
                self._append("EXPORT_COMPLETED", {"summary": summary, "files": refs})
                return freeze_json(summary)
            except Exception:
                if not self._poisoned:
                    self._append("EXPORT_FAILED", {"failure_code": "EXPORT_INCOMPLETE_PARTIAL_FILES_RETAINED"})
                self._poisoned = True
                raise
