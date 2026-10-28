"""WP07 selected-source illustrative outcomes, not learner measurement.

No native read/submit, CPC admission, implicit recipe or core wire change.
Source/rights/review assertions and hashes are not external authority.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import hashlib
import os
from pathlib import Path
from typing import Any, Mapping
import uuid

from .controller import OfflineController
from .episode import project_events
from .ledger import (AppendOnlyLedger, LedgerScope, SnapshotReference, SnapshotStore, LedgerCorruptionError,
                     _real_directory, _new_file, _checked_fd, _read_file, _fsync_directory)
from .native_capture import load_capture
from .native_contract import LedgerRecord, RecordKind
from .primitives import (ContractError, canonical_json_bytes, decode_json_object, freeze_json, plain_json,
                         require_identifier, require_digest, require_mapping, require_text)

COMPOSITE_FIELDS = ("experiment_id", "experiment_version", "unit_token", "exposure_record_id",
                    "exposure_digest", "outcome_key", "purpose")


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def new_ref(prefix: str) -> str:
    return prefix + ":" + uuid.uuid4().hex


def cpc_identifier(value: Any, field: str) -> str:
    """Frozen CPC2.0.1 wire identifier domain, without extra normalization."""
    if (type(value) is not str or not 0 < len(value) <= 256 or value != value.strip()
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise ContractError(field + ": invalid CPC identifier")
    return value


@dataclass(frozen=True, slots=True)
class Composite:
    experiment_id: str
    experiment_version: str
    unit_token: str
    exposure_record_id: str
    exposure_digest: str
    outcome_key: str
    purpose: str

    def __post_init__(self):
        for name in COMPOSITE_FIELDS:
            (require_digest if name == "exposure_digest" else cpc_identifier)(getattr(self, name), name)

    def to_mapping(self) -> dict:
        return {name: getattr(self, name) for name in COMPOSITE_FIELDS}

    @classmethod
    def interpret(cls, value: Any) -> Composite | None:
        # Additional metadata never changes a seven-field identity.
        if not isinstance(value, Mapping):
            return None
        try:
            return cls(**{name: value[name] for name in COMPOSITE_FIELDS})
        except (KeyError, TypeError, ContractError):
            return None


def typed_value(value: Any, depth: int = 0, budget=None):
    """Preserve invalid external values without JSON NaN/bool-int coercion."""
    budget = [1048576] if budget is None else budget
    budget[0] -= 32
    if depth > 32 or budget[0] < 0:
        raise ContractError("external row exceeds supported value depth")
    if value is None:
        return {"type": "null"}
    if type(value) is bool:
        return {"type": "bool", "value": value}
    if type(value) is int:
        decimal = str(value)
        budget[0] -= len(decimal)
        if budget[0] < 0:
            raise ContractError("external integer exceeds row budget")
        return {"type": "int", "decimal": decimal}
    if type(value) is float:
        return {"type": "float", "hex": value.hex()}
    if type(value) is str:
        if len(value) > 1048576:
            raise ContractError("external text exceeds supported bound")
        budget[0] -= len(value.encode("utf-8", errors="surrogatepass"))
        if budget[0] < 0:
            raise ContractError("external row exceeds supported byte budget")
        try:
            value.encode("utf-8", errors="strict")
            return {"type": "str", "value": value}
        except UnicodeError:
            return {"type": "str-surrogatepass", "hex": value.encode("utf-8", errors="surrogatepass").hex()}
    if type(value) in (list, tuple):
        return {"type": "array", "items": [typed_value(v, depth + 1, budget) for v in value]}
    if isinstance(value, Mapping) and all(type(k) is str for k in value):
        if any(len(k) > 1048576 for k in value):
            raise ContractError("external key exceeds bound")
        return {"type": "object", "items": [{"key": typed_value(k, depth + 1, budget),
            "value": typed_value(v, depth + 1, budget)} for k, v in value.items()]}
    raise ContractError("unsupported external value type")


@dataclass(frozen=True, slots=True)
class ExternalRow:
    """Every supplied row survives; an interpretable key counts before validity."""
    row_ref: str | None
    composite: Composite | None
    descriptor: Mapping
    scalar_type: str
    integer_value: int | None
    measure_state: Any
    rubric_id: Any
    rubric_version: Any
    recipe_digest: Any
    lineage_ref: Any
    shape_valid: bool

    def __post_init__(self):
        if self.composite is not None and type(self.composite) is not Composite:
            raise ContractError("typed external composite required")
        # Public typed instances must not bypass the raw-row factory's metadata
        # domain. Preserve invalid values in descriptor, normalize metadata only.
        for name in ("row_ref", "measure_state", "rubric_id", "rubric_version", "recipe_digest", "lineage_ref"):
            try:
                normalized = (require_digest if name == "recipe_digest" else require_identifier)(getattr(self, name), name)
            except ContractError:
                normalized = None
            object.__setattr__(self, name, normalized)
        object.__setattr__(self, "shape_valid", self.shape_valid is True and self.row_ref is not None)
        object.__setattr__(self, "descriptor", freeze_json(self.descriptor))

    @classmethod
    def from_mapping(cls, row: Mapping) -> ExternalRow:
        if not isinstance(row, Mapping):
            return cls(None, None, freeze_json(typed_value(row)), "unsupported", None,
                       None, None, None, None, None, False)
        descriptor = freeze_json(typed_value(row))
        ref = row.get("row_ref")
        try:
            ref = require_identifier(ref, "row_ref")
        except ContractError:
            ref = None
        value = row.get("value")
        allowed = {"row_ref", "composite", "value", "measure_state", "rubric_id", "rubric_version", "recipe_digest", "lineage_ref"}
        def metadata(name, digest=False):
            try:
                return (require_digest if digest else require_identifier)(row.get(name), name)
            except ContractError:
                return None
        return cls(ref, Composite.interpret(row.get("composite")), descriptor, type(value).__name__,
            value if type(value) is int else None, metadata("measure_state"), metadata("rubric_id"),
            metadata("rubric_version"), metadata("recipe_digest", True), metadata("lineage_ref"),
            allowed <= set(row) and set(row) <= allowed | {"lineage"} and ref is not None)


@dataclass(frozen=True, slots=True)
class OutcomeRecipe:
    """Exact response lookup is an author-stipulated supported fixture domain.

    Empty response is MISSING; unknown/invalid UTF8 is INVALID. No generic parse,
    trimming, score-from-hash/composite, default zero or pedagogical claim.
    """
    raw: bytes = field(repr=False)
    data: Mapping = field(init=False, repr=False)
    digest: str = field(init=False)

    def __post_init__(self):
        if type(self.raw) is not bytes or not 0 < len(self.raw) <= 1048576:
            raise ContractError("recipe: bounded canonical bytes required")
        row = require_mapping(decode_json_object(self.raw), "recipe", required=("format", "rubric_id", "rubric_version",
            "task_version_ref", "followup_item_digest", "followup_presentation_digest", "review_ref", "rights_ref", "responses"))
        if canonical_json_bytes(row) != self.raw or row["format"] != "wss-response-recipe-v1":
            raise ContractError("recipe: unsupported format/encoding")
        for name in ("rubric_id", "rubric_version", "task_version_ref", "review_ref", "rights_ref"):
            require_identifier(row[name], name)
        for name in ("followup_item_digest", "followup_presentation_digest"):
            require_digest(row[name], name)
        table = row["responses"]
        if type(table) is not dict or not 1 <= len(table) <= 256:
            raise ContractError("recipe: nonempty finite response lookup required")
        for response, score in table.items():
            require_text(response, "recipe.response", max_chars=1048576)
            if type(score) is not int or not 0 <= score <= 4:
                raise ContractError("recipe: exact integer0..4 required")
        object.__setattr__(self, "data", freeze_json(row))
        object.__setattr__(self, "digest", sha(self.raw))

    def score(self, raw: bytes) -> tuple[str, int | None]:
        if type(raw) is not bytes:
            raise ContractError("response: immutable bytes required")
        if not raw:
            return "MISSING", None
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeError:
            return "INVALID", None
        value = self.data["responses"].get(text)
        return ("INVALID", None) if value is None else ("VALID", value)


def read_analysis(controller: OfflineController, reference: SnapshotReference) -> dict:
    """Read-only validate a registered WP03 analysis against its exact prefix."""
    if type(controller) is not OfflineController:
        raise ContractError("controller required")
    # Narrow, version-pinned WP03 private interface keeps head/registry/bytes/
    # prefix from one cooperative controller-lock observation. Never nested view().
    with controller._command(readonly=True):
        current = controller._state()
        raw = controller.store.get(reference)
        row = require_mapping(decode_json_object(raw), "analysis", required=("format", "analysis_ref",
            "supersedes_analysis_ref", "reason", "basis_sequence", "view"))
        if row["format"] != "wss-episode-analysis-v1" or row["analysis_ref"] not in current["analyses"]:
            raise ContractError("analysis is not registered")
        registered = current["analyses"][row["analysis_ref"]]
        if plain_json(registered["analysis_snapshot"]) != reference.to_mapping():
            raise ContractError("analysis reference differs from registered bytes")
        basis = row["basis_sequence"]
        events = controller._events()
        if type(basis) is not int or not 1 <= basis < len(events):
            raise ContractError("analysis basis sequence invalid")
        expected = project_events(events[:basis])
        if canonical_json_bytes(expected) != canonical_json_bytes(row["view"]):
            raise ContractError("analysis view differs from controller prefix")
        return {"raw": raw, "document": row, "view": expected, "events": events[:basis],
            "current_head": next(reversed(current["analyses"])), "reference": reference.to_mapping()}


def exposure_metadata(raw: bytes) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= 1048576:
        raise ContractError("exposure metadata requires bounded bytes")
    row = decode_json_object(raw)
    if row.get("record_type") != "exposure" or type(row.get("integrity")) is not dict:
        raise ContractError("not a final exposure record")
    digest = sha(canonical_json_bytes({k: v for k, v in row.items() if k != "integrity"}))
    if row["integrity"].get("content_digest") != digest:
        raise ContractError("final exposure content digest mismatch")
    for name in ("record_id", "unit_token", "experiment_id", "experiment_version"):
        cpc_identifier(row.get(name), name)
    require_mapping(row.get("payload"), "exposure payload", required=("invocation_id", "enacted_condition",
        "artifact_version", "artifacts", "commitment", "release_attestation"))
    cpc_identifier(row["payload"]["invocation_id"], "invocation_id")
    return row


def selected_source(controller: OfflineController, basis: dict, attempt_ref: str):
    view = basis["view"]
    if attempt_ref not in view["attempts"]:
        raise ContractError("native attempt unavailable")
    attempt = view["attempts"][attempt_ref]
    selected = attempt["selected_followup"]
    if selected is None:
        raise ContractError("no selected followup; no replacement allowed")
    follow = view["followups"][selected]
    operation = view["operations"][follow["operation_ref"]]
    if follow["post_close_revision"] or operation["attempt_ref"] != attempt_ref or operation["kind"] != "FOLLOWUP":
        raise ContractError("followup selection/binding invalid")
    occurrence = view["occurrences"][follow["occurrence_key"]]
    capture_ref = SnapshotReference.from_mapping(occurrence["capture_snapshot"])
    capture = load_capture(capture_ref, controller.store)
    if capture.metadata_issues or capture.transport.receipt.operation_ref != follow["operation_ref"]:
        raise ContractError("followup capture metadata unresolved")
    receipt = capture.transport.receipt
    source, snapshot, event = receipt.source, receipt.snapshots[0], receipt.occurrences[0]
    if source is None or source.source_epoch_ref != controller.context.source.source_epoch_ref:
        raise ContractError("source epoch conflict")
    raw = next(blob.content for blob in capture.transport.blobs if blob.ref == snapshot.value_bytes_ref)
    if sha(raw) != snapshot.value_digest:
        raise ContractError("selected value bytes mismatch")
    return attempt, follow, capture, snapshot, event, raw


class OutcomeStore:
    """Append-only derivation receipts and source ownership within this store.

    No global clone detection or writable reopen. Existing external rows can be
    reused against newer analysis mappings; a first response is never reselected.
    """
    def __init__(self, root, run_ref, journal, snapshots, writable):
        self.root, self.run_ref, self.journal, self.snapshots = root, run_ref, journal, snapshots
        self._writable, self._poisoned = writable, False
        self._metadata = canonical_json_bytes({"format": "wss-outcomes-v1.1", "scope": journal.scope.to_mapping(),
                                               "store_ref": snapshots._store_ref})

    @classmethod
    def create(cls, root, run_ref):
        require_identifier(run_ref, "outcome run_ref")
        target = _real_directory(root, exists=False)
        target.mkdir(mode=0o700, exist_ok=False)
        scope = LedgerScope(new_ref("outcome-ledger"), run_ref, "OFFLINE_SOURCE_OUTCOMES")
        store_ref = new_ref("outcome-store")
        _new_file(target / "outcomes.meta.json", canonical_json_bytes({"format": "wss-outcomes-v1.1",
            "scope": scope.to_mapping(), "store_ref": store_ref}))
        _new_file(target / ".outcomes.lock", b"")
        journal = AppendOnlyLedger.create(target / "journal", scope)
        store = SnapshotStore.create(target / "snapshots", store_ref)
        _fsync_directory(target)
        _fsync_directory(target.parent)
        return cls(target, run_ref, journal, store, True)

    @classmethod
    def open_readonly(cls, root, run_ref):
        target = _real_directory(root, exists=True)
        meta = decode_json_object(_read_file(target / "outcomes.meta.json", 1048576))
        scope = LedgerScope(**meta["scope"])
        if meta.get("format") != "wss-outcomes-v1.1" or scope.run_ref != run_ref:
            raise ContractError("outcome scope mismatch")
        result = cls(target, run_ref, AppendOnlyLedger.open_existing(target / "journal", scope),
                     SnapshotStore.open_existing(target / "snapshots", meta["store_ref"]), False)
        result.view()
        return result

    @contextmanager
    def _lock(self, write):
        if write and (not self._writable or self._poisoned):
            raise ContractError("outcome store readonly or uncertain")
        fd = _checked_fd(self.root / ".outcomes.lock", os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            _real_directory(self.root, exists=True)
            if _read_file(self.root / "outcomes.meta.json", 1048576) != self._metadata:
                raise LedgerCorruptionError("outcome store metadata mismatch")
            if write and self._poisoned:
                raise ContractError("outcome store uncertain")
            yield
        except Exception:
            if write:
                self._poisoned = True
            raise
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _append(self, event, data):
        ref = new_ref("outcome-event")
        try:
            self.journal.append(LedgerRecord(ref, RecordKind.AUDIT_REFERENCE, ref,
                {"audit_ref": ref, "status": "RECORDED", "format": "wss-outcomes-v1.1", "event": event, "data": data}))
        except Exception:
            self._poisoned = True
            raise

    def _save(self, prefix, raw):
        try:
            ref = self.snapshots.put(new_ref(prefix), raw)
            if self.snapshots.get(ref) != raw:
                raise LedgerCorruptionError("outcome snapshot readback")
            return ref
        except Exception:
            self._poisoned = True
            raise

    def _view(self):
        attempts, outputs = {}, []
        for record in self.journal.read_records():
            p = plain_json(record.payload)
            if (record.kind is not RecordKind.AUDIT_REFERENCE or p.get("format") != "wss-outcomes-v1.1"
                    or set(p) != {"audit_ref", "status", "format", "event", "data"}):
                raise LedgerCorruptionError("unexpected outcome journal record")
            event, data = p["event"], p["data"]
            ref = data["derivation_ref"]
            if event == "STARTED":
                if ref in attempts:
                    raise LedgerCorruptionError("duplicate derivation")
                if set(data) != {"derivation_ref", "analysis_reference", "controller_scope", "requested_purpose"}:
                    raise LedgerCorruptionError("started receipt shape")
                attempts[ref] = {**data, "status": "PENDING", "input_snapshots": {}, "output_snapshots": {}, "failure_stage": None}
            elif event == "INPUTS_CAPTURED":
                if (attempts[ref]["status"] != "PENDING" or set(data) != {"derivation_ref", "snapshots"}
                        or set(data["snapshots"]) != {"exposure", "recipe"}):
                    raise LedgerCorruptionError("derivation event order")
                for snapshot in data["snapshots"].values():
                    self.snapshots.get(SnapshotReference.from_mapping(snapshot))
                attempts[ref]["status"] = "INPUTS_CAPTURED"
                attempts[ref]["input_snapshots"] = data["snapshots"]
            elif event == "DERIVED":
                if (attempts[ref]["status"] != "INPUTS_CAPTURED" or set(data) != {"derivation_ref", "snapshots"}
                        or set(data["snapshots"]) != {"analysis", "value", "native_transport", "recipe", "exposure", "outcome"}
                        or any(data["snapshots"][k] != v for k, v in attempts[ref]["input_snapshots"].items())):
                    raise LedgerCorruptionError("derivation event order")
                for snapshot in data["snapshots"].values():
                    self.snapshots.get(SnapshotReference.from_mapping(snapshot))
                outcome = decode_json_object(self.snapshots.get(SnapshotReference.from_mapping(data["snapshots"]["outcome"])))
                outputs.append(outcome)
                attempts[ref].update(status="DERIVED", outcome_ref=outcome["row_ref"], output_snapshots=data["snapshots"])
            elif event == "FAILED":
                if (attempts[ref]["status"] not in {"PENDING", "INPUTS_CAPTURED"}
                        or set(data) != {"derivation_ref", "failure_code"}):
                    raise LedgerCorruptionError("failure event order")
                attempts[ref].update(failure_stage=attempts[ref]["status"], status="FAILED", failure_code=data["failure_code"])
            else:
                raise LedgerCorruptionError("unknown outcome event")
        referenced = {self.snapshots._path(ref["snapshot_ref"]).name for a in attempts.values()
                      for ref in [*a["input_snapshots"].values(), *a["output_snapshots"].values()]}
        orphan_files = sorted(p.name for p in (self.root / "snapshots").glob("*.bin") if p.name not in referenced)
        return {"derivations": list(attempts.values()), "outcomes": outputs, "orphan_snapshot_files": orphan_files,
            "counts": {"received_derivations": len(attempts), "external_rows": len(outputs),
                "failed_derivations": sum(a["status"] == "FAILED" for a in attempts.values()),
                "pending_derivations": sum(a["status"] in {"PENDING", "INPUTS_CAPTURED"} for a in attempts.values())}}

    def view(self):
        with self._lock(False):
            return freeze_json(self._view())

    def derive(self, controller, analysis_reference, exposure_raw: bytes, recipe: OutcomeRecipe, purpose: str):
        """Read saved native-shaped facts only; failures retain derivation receipt."""
        with self._lock(True):
            derivation = new_ref("derivation")
            try:
                requested_purpose = cpc_identifier(purpose, "purpose")
            except ContractError:
                requested_purpose = None
            self._append("STARTED", {"derivation_ref": derivation,
                "requested_purpose": requested_purpose,
                "analysis_reference": analysis_reference.to_mapping() if type(analysis_reference) is SnapshotReference else None,
                "controller_scope": controller.scope.to_mapping() if type(controller) is OfflineController else None})
            try:
                if type(recipe) is not OutcomeRecipe:
                    raise ContractError("explicit frozen recipe required")
                cpc_identifier(purpose, "purpose")
                input_refs = {"exposure": self._save("received-exposure", exposure_raw).to_mapping(),
                              "recipe": self._save("received-recipe", recipe.raw).to_mapping()}
                self._append("INPUTS_CAPTURED", {"derivation_ref": derivation, "snapshots": input_refs})
                exposure = exposure_metadata(exposure_raw)
                basis = read_analysis(controller, analysis_reference)
                attempt_ref = exposure["unit_token"]
                attempt, follow, capture, snapshot, event, raw = selected_source(controller, basis, attempt_ref)
                invocation = basis["view"]["invocations"].get(exposure["payload"]["invocation_id"])
                condition = {"WSS-U01-HINT": "hint", "WSS-U01-ANSWER": "answer"}.get(attempt["logical_resource"])
                if (invocation is None or invocation["attempt_ref"] != attempt_ref or not invocation["ever_published"]
                        or exposure["payload"]["enacted_condition"] != condition):
                    raise ContractError("exposure does not bind selected attempt publication")
                expected = controller.context.followup_target
                if (recipe.data["task_version_ref"] != controller.context.task_version_ref
                        or recipe.data["followup_item_digest"] != snapshot.item_digest
                        or recipe.data["followup_presentation_digest"] != snapshot.item_presentation_digest
                        or snapshot.item_id != expected.item_id):
                    raise ContractError("source/recipe binding mismatch")
                source_key = [capture.transport.receipt.source.source_epoch_ref, event.standard_log_record_id, snapshot.item_id]
                for old in self._view()["outcomes"]:
                    if old["lineage"]["source_key"] == source_key:
                        raise ContractError("selected source already owned; no clone/rederive")
                outcome_key = new_ref("outcome-key")
                composite = Composite(exposure["experiment_id"], exposure["experiment_version"], attempt_ref,
                    exposure["record_id"], exposure["integrity"]["content_digest"], outcome_key, purpose)
                state, value = recipe.score(raw)
                outcome = {"row_ref": new_ref("external-row"), "composite": composite.to_mapping(),
                    "measure_state": state, "value": value, "rubric_id": recipe.data["rubric_id"],
                    "rubric_version": recipe.data["rubric_version"], "recipe_digest": recipe.digest,
                    "lineage_ref": derivation,
                    "lineage": {"source_key": source_key, "attempt_ref": attempt_ref,
                        "followup_ref": follow["followup_ref"], "operation_ref": follow["operation_ref"],
                        "analysis_ref": basis["document"]["analysis_ref"], "basis_sequence": basis["document"]["basis_sequence"],
                        "controller_scope": controller.scope.to_mapping(), "source_snapshot": snapshot.to_mapping(),
                        "value_digest": sha(raw), "recipe_digest": recipe.digest,
                        "source_epoch": capture.transport.receipt.source.to_mapping(),
                        "native_occurrence": event.to_mapping(), "capture_reference": capture.manifest_reference.to_mapping()}}
                blobs = {"analysis": basis["raw"], "value": raw,
                    "native_transport": controller.store.get(capture.raw_reference)}
                refs = {name: self._save("outcome-" + name, data).to_mapping() for name, data in blobs.items()}
                refs.update(input_refs)
                refs["outcome"] = self._save("external-outcome", canonical_json_bytes(outcome)).to_mapping()
                self._append("DERIVED", {"derivation_ref": derivation, "snapshots": refs})
                return freeze_json(outcome)
            except Exception:
                if not self._poisoned:
                    self._append("FAILED", {"derivation_ref": derivation, "failure_code": "SOURCE_DERIVATION_FAILED"})
                raise


def external_from_outcome(outcome: Mapping) -> ExternalRow:
    return ExternalRow.from_mapping({key: outcome[key] for key in ("row_ref", "composite", "measure_state", "value",
        "rubric_id", "rubric_version", "recipe_digest", "lineage_ref")})
