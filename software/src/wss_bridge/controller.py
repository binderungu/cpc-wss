"""Explicit local-only WP03 controller. This module cannot submit or read Moodle.

A writable handle is issued only by create(). Reopening is read-only; uncertain
writes are never retried/repaired by this API. Local acknowledgments certify
persisted local bookkeeping, not external authority, publication truth or CPC.
"""
from __future__ import annotations

import fcntl
import os
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Any, Iterator, Mapping

from .episode import STAGES, project_events
from .ledger import (AppendOnlyLedger, LedgerScope, SnapshotReference, SnapshotStore,
    LedgerError, LedgerCorruptionError, _checked_fd, _new_file, _real_directory, _fsync_directory)
from .native_contract import (ActorBinding, LedgerRecord, NativeReadStatus, NativeTarget,
    SourceIdentity, ObservationRelation, RecordKind, classify_observations)
from .native_capture import persist_raw, check_and_store_capture, load_capture
from .primitives import (ContractError, canonical_json_bytes, decode_json_object, freeze_json,
    plain_json, require_identifier, optional_identifier, require_digest, require_int, require_bool)

FORMAT = "wss-controller-v2"
SLOTS = (0, 1000, 5000)
RESOURCES = frozenset({"WSS-U01-HINT", "WSS-U01-ANSWER"})
CONFIGS = frozenset({"G_BASE", "G_STYLE", "G_CAP", "G_RATIONALE", "G_SEED"})


def _ref(prefix: str) -> str:
    return prefix + ":" + str(uuid.uuid4())


class WorkflowRefused(ContractError):
    """A local sequencing refusal; no external action was attempted."""


@dataclass(frozen=True)
class ControllerContext:
    source: SourceIdentity
    actor: ActorBinding
    task_target: NativeTarget
    followup_target: NativeTarget
    task_version_ref: str
    context_version_ref: str
    clean_interval_evidence_ref: str | None = None
    prior_operations_evidence_ref: str | None = None
    sole_writer_evidence_ref: str | None = None
    pending_facts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, cls in (("source", SourceIdentity), ("actor", ActorBinding), ("task_target", NativeTarget), ("followup_target", NativeTarget)):
            if not isinstance(getattr(self, name), cls):
                raise ContractError(f"context.{name}: unexpected type")
        for name in ("task_version_ref", "context_version_ref"):
            require_identifier(getattr(self, name), name)
        for name in ("clean_interval_evidence_ref", "prior_operations_evidence_ref", "sole_writer_evidence_ref"):
            optional_identifier(getattr(self, name), name)
        if not isinstance(self.pending_facts, (tuple, list)):
            raise ContractError("pending_facts: expected an array")
        object.__setattr__(self, "pending_facts", tuple(require_identifier(v, "pending_fact") for v in self.pending_facts))

    def to_mapping(self) -> dict[str, Any]:
        return {f.name: (getattr(self, f.name).to_mapping() if f.name in ("source", "actor", "task_target", "followup_target")
                else list(self.pending_facts) if f.name == "pending_facts" else getattr(self, f.name)) for f in fields(self)}

    def readiness_issues(self) -> tuple[str, ...]:
        issues = list(self.pending_facts)
        if any(v is None for v in self.source.to_mapping().values()):
            issues.append("SOURCE_IDENTITY_UNRESOLVED")
        if self.actor.actor_ref is None or self.actor.registry_ref is None or not self.actor.expected_userid:
            issues.append("ACTOR_REGISTRY_UNRESOLVED")
        if self.clean_interval_evidence_ref is None and self.prior_operations_evidence_ref is None:
            issues.append("CLEAN_INTERVAL_UNVERIFIED")
        if self.sole_writer_evidence_ref is None:
            issues.append("SOLE_WRITER_UNVERIFIED")
        for target in (self.task_target, self.followup_target):
            required = ("target_ref", "courseid", "cmid", "feedback_id", "item_id", "contextid", "contextlevel", "eventname", "objecttable", "item_type", "item_digest", "item_presentation_digest")
            if any(getattr(target, k) in (None, 0, "") for k in required):
                issues.append("TARGET_UNRESOLVED")
            if target.source_epoch_ref != self.source.source_epoch_ref:
                issues.append("SOURCE_EPOCH_CONFLICT")
            if target.eventname != "\\mod_feedback\\event\\response_submitted" or target.objecttable != "feedback_completed" or target.contextlevel != 70:
                issues.append("UNSUPPORTED_NATIVE_ROUTE")
            if target.feedback_route != "ordinary_course":
                issues.append("FEEDBACK_ROUTE_UNRESOLVED" if target.feedback_route is None else "UNSUPPORTED_FEEDBACK_ROUTE")
            if target.response_scope_courseid != 0:
                issues.append("RESPONSE_SCOPE_UNRESOLVED" if target.response_scope_courseid is None else "UNSUPPORTED_RESPONSE_SCOPE")
        if self.task_target.target_ref == self.followup_target.target_ref or self.task_target.cmid == self.followup_target.cmid:
            issues.append("TASK_FOLLOWUP_SCOPE_CONFLICT")
        return tuple(sorted(set(issues)))


class OfflineController:
    """One actor/task local protocol, explicit IO only; no writable recovery API."""
    def __init__(self, root: Path, scope: LedgerScope, context: ControllerContext,
                 journal: AppendOnlyLedger, store: SnapshotStore, writable: bool) -> None:
        self.root, self.scope, self.context = root, scope, context
        self.journal, self.store = journal, store
        self._writable, self._poisoned = writable, False

    @classmethod
    def create(cls, root: str | Path, scope: LedgerScope, context: ControllerContext) -> OfflineController:
        if not isinstance(context, ControllerContext) or not isinstance(scope, LedgerScope):
            raise ContractError("controller: expected typed scope/context")
        if scope.source_epoch_ref != context.source.source_epoch_ref:
            raise ContractError("controller scope/source epoch differs")
        root = _real_directory(root, exists=False)
        root.mkdir(mode=0o700)
        _new_file(root / ".controller.lock", b"")
        journal = AppendOnlyLedger.create(root / "journal", scope)
        store = SnapshotStore.create(root / "snapshots", scope.ledger_ref + ":snapshots")
        _fsync_directory(root)
        _fsync_directory(root.parent)
        handle = cls(root, scope, context, journal, store, True)
        with handle._command():
            handle._append("CONTEXT", context.to_mapping())
        return handle

    @classmethod
    def open_readonly(cls, root: str | Path, scope: LedgerScope, expected_context: ControllerContext) -> OfflineController:
        if not isinstance(scope, LedgerScope) or not isinstance(expected_context, ControllerContext):
            raise ContractError("controller: expected typed scope/context")
        root = _real_directory(root, exists=True)
        handle = cls(root, scope, expected_context,
            AppendOnlyLedger.open_existing(root / "journal", scope),
            SnapshotStore.open_existing(root / "snapshots", scope.ledger_ref + ":snapshots"), False)
        handle.view()
        return handle

    @contextmanager
    def _command(self, *, readonly: bool = False) -> Iterator[None]:
        if not readonly and (not self._writable or self._poisoned):
            raise WorkflowRefused("controller: read-only or poisoned handle")
        descriptor = None
        try:
            _real_directory(self.root, exists=True)
            descriptor = _checked_fd(self.root / ".controller.lock", os.O_RDONLY)
            fcntl.flock(descriptor, fcntl.LOCK_SH if readonly else fcntl.LOCK_EX)
            # A waiting command may have passed the optimistic check before
            # the previous lock holder poisoned this shared writable handle.
            if not readonly and (not self._writable or self._poisoned):
                raise WorkflowRefused("controller: handle became poisoned while waiting")
            yield
        except (OSError, LedgerError):
            if not readonly:
                self._poisoned = True
            raise
        finally:
            if descriptor is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def _events(self) -> list[dict[str, Any]]:
        events = []
        for seq, record in enumerate(self.journal.read_records(), 1):
            if record.kind is not RecordKind.AUDIT_REFERENCE:
                raise LedgerCorruptionError("controller: unexpected non-command record")
            payload = plain_json(record.payload)
            if set(payload) != {"audit_ref", "status", "format", "event", "data"} or payload["format"] != FORMAT:
                raise LedgerCorruptionError("controller: invalid command record")
            data = payload["data"]
            # Every command can reference exact byte objects; verify on every
            # read-only replay as well as before an acknowledgment.
            for key in ("raw_snapshot", "analysis_snapshot"):
                if key in data:
                    self.store.get(SnapshotReference.from_mapping(data[key]))
            if data.get("capture_snapshot") is not None:
                try:
                    load_capture(SnapshotReference.from_mapping(data["capture_snapshot"]), self.store)
                except ContractError as exc:
                    raise LedgerCorruptionError("controller: persisted capture is invalid") from exc
            events.append({"event": payload["event"], "data": data, "sequence": seq})
        return events

    def _state(self) -> Mapping[str, Any]:
        state = project_events(self._events())
        if state["context"] != freeze_json(self.context.to_mapping()):
            raise LedgerCorruptionError("controller: expected context differs from durable context")
        return state

    def _append(self, event: str, data: Mapping[str, Any]) -> None:
        audit = _ref("command")
        self.journal.append(LedgerRecord(audit, RecordKind.AUDIT_REFERENCE, audit,
            {"audit_ref": audit, "status": "RECORDED", "format": FORMAT, "event": event, "data": data}))

    def view(self) -> Mapping[str, Any]:
        with self._command(readonly=True):
            return self._state()

    @staticmethod
    def _running(state: Mapping[str, Any]) -> None:
        if state["stopped_flags"]:
            raise WorkflowRefused("controller: stopped branch requires a separate disposition; no automatic recovery")

    def opportunity(self, *, note_ref: str) -> str:
        require_identifier(note_ref, "note_ref")
        with self._command():
            self._state()
            ref = _ref("opportunity")
            self._append("OPPORTUNITY", {"opportunity_ref": ref, "note_ref": note_ref})
            return ref

    def begin_operation(self, opportunity_ref: str, kind: str, *, controlled_value_digest: str,
                        log_watermark: int, attempt_ref: str | None = None,
                        logical_resource: str | None = None, config_id: str | None = None) -> str:
        require_identifier(opportunity_ref, "opportunity_ref")
        require_digest(controlled_value_digest, "controlled_value_digest")
        require_int(log_watermark, "log_watermark")
        optional_identifier(attempt_ref, "attempt_ref")
        if kind not in ("TASK", "FOLLOWUP"):
            raise ContractError("operation kind: expected TASK or FOLLOWUP")
        with self._command():
            state = self._state()
            self._running(state)
            if self.context.readiness_issues():
                raise WorkflowRefused("controller: unresolved declared context")
            if opportunity_ref not in state["opportunities"]:
                raise WorkflowRefused("controller: opportunity not recorded")
            if state["pending_operation"] is not None or any(not c["settled"] for c in state["invocations"].values()):
                raise WorkflowRefused("controller: operation/request remains unsettled")
            if any(o["opportunity_ref"] == opportunity_ref for o in state["operations"].values()):
                raise WorkflowRefused("controller: opportunity already used")
            revision = False
            if kind == "TASK":
                if attempt_ref is not None or logical_resource not in RESOURCES or config_id not in CONFIGS:
                    raise ContractError("task operation: requires one prospective resource/config assignment")
            else:
                if attempt_ref not in state["attempts"] or logical_resource is not None or config_id is not None:
                    raise WorkflowRefused("followup operation: requires an existing attempt, no new condition")
                attempt = state["attempts"][attempt_ref]
                revision = attempt["closed_sequence"] is not None
                if revision and attempt["closure_status"] != "CLOSED":
                    raise WorkflowRefused("followup revision: prior closure is unresolved")
                if not revision and state["active_attempt"] != attempt_ref:
                    raise WorkflowRefused("followup operation: attempt is not active")
            ref = _ref("operation")
            target = self.context.task_target if kind == "TASK" else self.context.followup_target
            self._append("OPERATION", {"operation_ref": ref, "opportunity_ref": opportunity_ref, "kind": kind,
                "attempt_ref": attempt_ref, "target_ref": target.target_ref, "controlled_value_digest": controlled_value_digest,
                "log_watermark": log_watermark, "logical_resource": logical_resource, "config_id": config_id,
                "post_close_revision": revision})
            return ref

    def record_completion(self, operation_ref: str, *, known: bool, evidence_ref: str) -> None:
        require_bool(known, "known")
        require_identifier(evidence_ref, "evidence_ref")
        with self._command():
            state = self._state()
            operation = state["operations"].get(operation_ref)
            if operation is None or operation["completion"] != "PENDING" or operation["status"] != "PENDING":
                raise WorkflowRefused("completion: unknown or already settled operation")
            self._append("COMPLETION", {"operation_ref": operation_ref, "known": known, "evidence_ref": evidence_ref})

    def _binding_issues(self, receipt: Any, operation: Mapping[str, Any]) -> list[str]:
        target = self.context.task_target if operation["kind"] == "TASK" else self.context.followup_target
        expected_target = replace(target, controlled_value_digest=operation["controlled_value_digest"])
        issues = list(receipt.binding_issues())
        for name, expected in (("source", self.context.source), ("actor", self.context.actor), ("target", expected_target)):
            supplied = getattr(receipt, name)
            if supplied is None or supplied.to_mapping() != expected.to_mapping():
                issues.append("EXPECTED_" + name.upper() + "_CONFLICT")
        for name in ("clean_interval_evidence_ref", "prior_operations_evidence_ref", "sole_writer_evidence_ref"):
            if getattr(receipt, name) != getattr(self.context, name):
                issues.append("EXPECTED_" + name.upper() + "_CONFLICT")
        if receipt.operation_ref != operation["operation_ref"]:
            issues.append("OPERATION_REF_CONFLICT")
        if receipt.log_watermark != operation["log_watermark"]:
            issues.append("WATERMARK_CONFLICT")
        if operation["completion"] != "KNOWN":
            issues.append("NATIVE_RESULT_UNRESOLVED")
        return sorted(set(issues))

    def observe(self, operation_ref: str, slot_ms: int, raw: bytes) -> Mapping[str, Any]:
        """Persist all supplied bytes before interpretation; return ACK only after replay.

        Slots are protocol labels, not elapsed-time measurements. Known operations
        allow at most three observations. No helper, wait or network is invoked.
        """
        require_int(slot_ms, "slot_ms")
        if slot_ms not in SLOTS or type(raw) is not bytes:
            raise ContractError("observe: supported slot and immutable bytes required")
        with self._command():
            state = self._state()
            operation = state["operations"].get(operation_ref)
            if operation is None:
                raise WorkflowRefused("observe: unknown prospective operation")
            first_unknown_result_audit = (operation["completion"] == "UNKNOWN" and not operation["slots"]
                and set(state["stopped_flags"]) == {"NATIVE_RESULT_UNRESOLVED"})
            if operation["status"] == "HELD" or (state["stopped_flags"] and operation["status"] != "CAPTURED" and not first_unknown_result_audit):
                raise WorkflowRefused("observe: stopped visibility branch; no further prospective progress")
            slots = operation["slots"]
            if len(slots) >= 3 or slot_ms != SLOTS[len(slots)]:
                raise WorkflowRefused("observe: slots must be 0/1000/5000 once, in order")
            ingestion = _ref("ingestion")
            raw_reference = persist_raw(raw, self.store)
            self.store.get(raw_reference)
            self._append("INGESTION", {"ingestion_ref": ingestion, "operation_ref": operation_ref,
                "slot_ms": slot_ms, "raw_snapshot": raw_reference.to_mapping()})
            try:
                bundle = check_and_store_capture(raw_reference, self.store)
            except ContractError:
                self._append("OBSERVATION", {"ingestion_ref": ingestion, "status": "HOLD",
                    "issues": ["INVALID_TRANSPORT"], "capture_snapshot": None})
                self._state()
                return freeze_json({"ingestion_ref": ingestion, "acknowledged": False, "status": "HOLD"})
            receipt = bundle.transport.receipt
            issues = self._binding_issues(receipt, operation)
            issues.extend(bundle.metadata_issues)
            capture_ref = bundle.manifest_reference.to_mapping()
            # NO_MATCH can advance only an otherwise coherent bound interval.
            wait_issues = {"NO_MATCH", "NATIVE_OCCURRENCE_UNAVAILABLE", "SOURCE_SNAPSHOT_UNAVAILABLE",
                "CAPTURE_STATUS_NOT_MATCH", "CAPTURE_OCCURRENCE_NOT_SINGLETON", "CAPTURE_SNAPSHOT_NOT_SINGLETON"}
            wait = receipt.status is NativeReadStatus.NO_MATCH and not (set(issues) - wait_issues)
            status, anchor, key = "HOLD", None, None
            # Source identity conflicts are retained even when a separate expected
            # value/target check also fails. Never rescue them by early filtering.
            if receipt.source is not None and receipt.source.source_epoch_ref is not None and len(receipt.occurrences) == 1 and receipt.occurrences[0].standard_log_record_id:
                observed_key = receipt.source.source_epoch_ref + ":" + str(receipt.occurrences[0].standard_log_record_id)
                prior = state["occurrences"].get(observed_key)
                if prior is not None:
                    key = observed_key
                    prior_receipt = load_capture(SnapshotReference.from_mapping(prior["capture_snapshot"]), self.store).transport.receipt
                    if classify_observations(prior_receipt, receipt) is ObservationRelation.SOURCE_CONFLICT:
                        issues.extend(["SOURCE_ID_CONFLICT", "SOURCE_MUTATION_UNEXPLAINED", "CLOSURE_UNRESOLVED"])
            if wait and slot_ms != SLOTS[-1]:
                status, issues = "WAIT", []
            elif wait:
                issues.append("NATIVE_OCCURRENCE_UNAVAILABLE_AT_DEADLINE")
            elif not issues:
                key = receipt.source.source_epoch_ref + ":" + str(receipt.occurrences[0].standard_log_record_id)
                old = state["occurrences"].get(key)
                if old is not None:
                    previous = load_capture(SnapshotReference.from_mapping(old["capture_snapshot"]), self.store).transport.receipt
                    relation = classify_observations(previous, receipt)
                    if relation is ObservationRelation.DUPLICATE_OBSERVATION and old["operation_ref"] == operation_ref:
                        status = "DUPLICATE"
                    else:
                        issues.append("SOURCE_ID_CONFLICT" if relation is ObservationRelation.SOURCE_CONFLICT else "OCCURRENCE_REUSED_ACROSS_OPERATIONS")
                elif operation["status"] != "PENDING":
                    issues.append("HOLD_LATE_EVIDENCE")
                elif operation["kind"] == "TASK":
                    status, anchor = "ACCEPTED", {"attempt_ref": _ref("attempt")}
                else:
                    attempt = state["attempts"][operation["attempt_ref"]]
                    if attempt["closed_sequence"] is not None and not operation["post_close_revision"]:
                        # The operation was prospective before closure, so its
                        # late arrival is not an established post-close revision.
                        issues.extend(["HOLD_LATE_EVIDENCE", "CLOSURE_UNRESOLVED"])
                    else:
                        status, anchor = "ACCEPTED", {"followup_ref": _ref("followup"), "attempt_ref": operation["attempt_ref"]}
            self._append("OBSERVATION", {"ingestion_ref": ingestion, "status": status,
                "issues": sorted(set(issues)), "capture_snapshot": capture_ref, "occurrence_key": key, "anchor": anchor})
            if "HOLD_LATE_EVIDENCE" in issues or "SOURCE_ID_CONFLICT" in issues:
                affected = operation["attempt_ref"]
                if operation["kind"] == "TASK":
                    affected = next((a["attempt_ref"] for a in state["attempts"].values() if a["operation_ref"] == operation_ref), None)
                if affected is None and key in state["occurrences"]:
                    old_operation = state["occurrences"][key]["operation_ref"]
                    affected = next((a["attempt_ref"] for a in state["attempts"].values() if a["operation_ref"] == old_operation), None)
                if affected is not None:
                    self._append("LATE_EVIDENCE", {"attempt_ref": affected, "ingestion_ref": ingestion})
                    self._analysis_unlocked("LATE_EVIDENCE")
            final = self._state()
            return freeze_json({"ingestion_ref": ingestion, "acknowledged": status in ("ACCEPTED", "DUPLICATE"),
                "status": status, "anchor": anchor, "sequence": final["sequence"]})

    def receive_help(self, attempt_ref: str, *, logical_resource: str, config_id: str) -> str:
        # Even malformed/unknown attempt strings are retained as supplied data
        # before precondition evaluation, using a fresh local invocation identity.
        with self._command():
            state = self._state()
            invocation = _ref("invocation")
            # Project malformed values to bounded explicit absence before the
            # durable RECEIVED record. Unsafe raw strings never enter journals.
            # This does not perform workflow precondition evaluation early.
            requested, invalid = {}, []
            for name, value in (("attempt_ref", attempt_ref), ("logical_resource", logical_resource), ("config_id", config_id)):
                try:
                    requested[name] = require_identifier(value, name)
                except ContractError:
                    requested[name] = None
                    invalid.append("INVALID_" + name.upper())
            self._append("INVOCATION_RECEIVED", {"invocation_ref": invocation, **requested,
                "native_lira_event_id": None, "reason_flags": invalid})
            attempt = state["attempts"].get(requested["attempt_ref"])
            reasons = list(invalid)
            if attempt is None:
                reasons.append("ATTEMPT_UNKNOWN")
            elif state["active_attempt"] != requested["attempt_ref"]:
                reasons.append("ATTEMPT_CLOSED_OR_INACTIVE")
            if state["pending_operation"] is not None:
                reasons.append("OPERATION_PENDING")
            if state["stopped_flags"]:
                reasons.append("BRANCH_STOPPED")
            if self.context.readiness_issues():
                reasons.append("CONTEXT_UNRESOLVED")
            if any(not v["settled"] for v in state["invocations"].values()):
                reasons.append("INVOCATION_PENDING")
            if attempt and (attempt["logical_resource"] != logical_resource or attempt["config_id"] != config_id):
                reasons.append("CONDITION_RESOURCE_CONFLICT")
            if reasons:
                self._append("INVOCATION_STAGE", {"invocation_ref": invocation, "stage": "PRECONDITION_REFUSED",
                    "evidence_ref": "local:precondition-refused", "reason_flags": reasons, "settled": True})
            self._state()
            return invocation

    def advance_invocation(self, invocation_ref: str, stage: str, *, evidence_ref: str) -> None:
        require_identifier(evidence_ref, "evidence_ref")
        with self._command():
            state = self._state()
            self._running(state)
            invocation = state["invocations"].get(invocation_ref)
            attempt = state["attempts"].get(invocation["attempt_ref"]) if invocation else None
            if invocation is None or invocation["settled"] or invocation["stage"] not in STAGES or attempt is None or attempt["closed_sequence"] is not None:
                raise WorkflowRefused("invocation: unknown/settled/not advanceable")
            expected = STAGES[STAGES.index(invocation["stage"]) + 1] if invocation["stage"] != STAGES[-1] else None
            if stage != expected:
                raise WorkflowRefused("invocation: transition must preserve all stages")
            data = {"invocation_ref": invocation_ref, "stage": stage, "evidence_ref": evidence_ref, "settled": False}
            if stage == "PUBLISHED":
                data["publication_ref"] = _ref("publication")
            self._append("INVOCATION_STAGE", data)

    def finish_invocation(self, invocation_ref: str, *, publication: str, evidence_ref: str) -> None:
        require_identifier(evidence_ref, "evidence_ref")
        if publication not in ("NONE", "PUBLISHED", "UNRESOLVED"):
            raise ContractError("publication: expected NONE, PUBLISHED or UNRESOLVED")
        with self._command():
            state = self._state()
            invocation = state["invocations"].get(invocation_ref)
            if invocation is None or invocation["settled"]:
                raise WorkflowRefused("invocation: unknown or already settled")
            # A later failure cannot erase an observed published exposure.
            if invocation["ever_published"]:
                stage = "PUBLISHED"
            elif publication == "UNRESOLVED":
                stage = "PUBLICATION_UNRESOLVED"
            elif publication == "NONE":
                stage = "FAILED_BEFORE_PUBLICATION"
            else:
                raise WorkflowRefused("publication: record ordered stages before known success")
            self._append("INVOCATION_STAGE", {"invocation_ref": invocation_ref, "stage": stage,
                "evidence_ref": evidence_ref, "settled": True,
                **({"publication_ref": next(p for p, v in state["publications"].items() if v["invocation_ref"] == invocation_ref)} if stage == "PUBLISHED" else {})})
            attempt = state["attempts"].get(invocation["attempt_ref"])
            if attempt is not None and attempt["closed_sequence"] is not None:
                self._append("LATE_EVIDENCE", {"attempt_ref": attempt["attempt_ref"], "invocation_ref": invocation_ref})
                self._analysis_unlocked("POST_CLOSE_INVOCATION_RESULT")

    def close_episode(self, attempt_ref: str, *, reason: str) -> None:
        if reason not in ("ABORT", "END_OF_SCRIPT"):
            raise ContractError("close reason: expected ABORT or END_OF_SCRIPT")
        with self._command():
            state = self._state()
            if attempt_ref not in state["attempts"] or state["attempts"][attempt_ref]["closed_sequence"] is not None:
                raise WorkflowRefused("close: unknown or already closed attempt")
            self._append("CLOSE", {"attempt_ref": attempt_ref, "reason": reason})

    def _analysis_unlocked(self, reason: str) -> SnapshotReference:
        state = self._state()
        analysis_ref = _ref("analysis")
        previous = next(reversed(state["analyses"]), None)
        raw = canonical_json_bytes({"format": "wss-episode-analysis-v1", "analysis_ref": analysis_ref,
            "supersedes_analysis_ref": previous, "reason": reason, "basis_sequence": state["sequence"], "view": state})
        snapshot = self.store.put(analysis_ref, raw)
        self.store.get(snapshot)
        self._append("ANALYSIS", {"analysis_ref": analysis_ref, "analysis_snapshot": snapshot.to_mapping(),
            "supersedes_analysis_ref": previous, "reason": reason})
        self._state()
        return snapshot

    def analysis_snapshot(self, *, reason: str = "EXPLICIT") -> SnapshotReference:
        require_identifier(reason, "reason")
        with self._command():
            return self._analysis_unlocked(reason)
