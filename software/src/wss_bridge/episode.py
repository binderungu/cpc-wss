"""Pure WP03 episode projection. Supplied facts are not native attestation."""
from __future__ import annotations

from typing import Any, Iterable, Mapping
from .primitives import ContractError, freeze_json, plain_json

TERMINAL_INVOCATION = frozenset({"PRECONDITION_REFUSED", "FAILED_BEFORE_PUBLICATION", "PUBLISHED", "PUBLICATION_UNRESOLVED"})
STAGES = ("RECEIVED", "CONSUME_STARTED", "CAPTURED", "COMMIT_DURABLE", "PUBLISHED")


def _flags(attempt: dict[str, Any], state: dict[str, Any]) -> list[str]:
    flags = list(attempt["flags"])
    calls = [v for v in state["invocations"].values() if v["attempt_ref"] == attempt["attempt_ref"]]
    published = sum(bool(v["ever_published"]) for v in calls)
    if published > 1:
        flags.append("HOLD_MULTI_INVOCATION")
    if any(v["publication_unresolved"] for v in calls):
        flags.append("HOLD_PUBLICATION_UNRESOLVED")
    if any(not v["settled"] for v in calls):
        flags.append("CLOSURE_UNRESOLVED")
    if any(o["attempt_ref"] == attempt["attempt_ref"] and o["status"] == "PENDING" for o in state["operations"].values()):
        flags.append("CLOSURE_UNRESOLVED")
    if attempt["selected_followup"] is None:
        flags.append("NO_SELECTED_FOLLOWUP")
    if published != 1:
        flags.append("SINGLE_EXPOSURE_NOT_ESTABLISHED")
    if attempt["selected_followup"] is not None and published == 0:
        flags.append("OUTCOME_BEFORE_EXPOSURE")
    return sorted(set(flags))


def _close(state: dict[str, Any], attempt: dict[str, Any], reason: str, sequence: int) -> None:
    if attempt["closed_sequence"] is not None:
        raise ContractError("episode: a later event cannot replace prior closure")
    if state["pending_operation"] is not None or any(not v["settled"] for v in state["invocations"].values() if v["attempt_ref"] == attempt["attempt_ref"]):
        attempt["flags"].append("CLOSURE_UNRESOLVED")
    attempt["closed_sequence"] = sequence
    attempt["close_reason"] = reason
    if state["active_attempt"] == attempt["attempt_ref"]:
        state["active_attempt"] = None


def project_events(events: Iterable[Mapping[str, Any]]) -> Mapping[str, Any]:
    """Replay local command history; caller separately verifies byte references.

    Every projection is fresh. Old analysis payloads and source events are never
    mutated. No scores, core dispositions, permissions or native IDs are created.
    """
    state: dict[str, Any] = {"context": None, "opportunities": {}, "operations": {}, "ingestions": {},
        "occurrences": {}, "attempts": {}, "invocations": {}, "publications": {}, "followups": {},
        "analyses": {}, "active_attempt": None, "pending_operation": None, "stopped_flags": [], "sequence": 0}
    for event in events:
        event = plain_json(event)
        kind, data, seq = event["event"], event["data"], event["sequence"]
        if seq != state["sequence"] + 1:
            raise ContractError("controller: noncontiguous command history")
        state["sequence"] = seq
        if kind == "CONTEXT":
            if state["context"] is not None or seq != 1:
                raise ContractError("controller: context must be first and unique")
            state["context"] = data
        elif kind == "OPPORTUNITY":
            state["opportunities"][data["opportunity_ref"]] = data
        elif kind == "OPERATION":
            state["operations"][data["operation_ref"]] = {**data, "status": "PENDING", "completion": "PENDING", "slots": []}
            state["pending_operation"] = data["operation_ref"]
        elif kind == "COMPLETION":
            state["operations"][data["operation_ref"]]["completion"] = "KNOWN" if data["known"] else "UNKNOWN"
            if not data["known"]:
                state["stopped_flags"].append("NATIVE_RESULT_UNRESOLVED")
        elif kind == "INGESTION":
            state["ingestions"][data["ingestion_ref"]] = {**data, "status": "RAW_DURABLE"}
            state["operations"][data["operation_ref"]]["slots"].append(data["slot_ms"])
        elif kind == "OBSERVATION":
            ingestion = state["ingestions"][data["ingestion_ref"]]
            ingestion.update(data)
            operation = state["operations"][ingestion["operation_ref"]]
            if data["status"] == "HOLD":
                operation["status"] = "HELD"
                state["stopped_flags"].extend(data["issues"])
                target = operation["attempt_ref"]
                affected = [a for a in state["attempts"].values() if a["attempt_ref"] == target or a["operation_ref"] == operation["operation_ref"]]
                old = state["occurrences"].get(data.get("occurrence_key"))
                if old is not None:
                    affected.extend(a for a in state["attempts"].values() if a["operation_ref"] == old["operation_ref"])
                for attempt in affected:
                    attempt["flags"].extend(data["issues"])
            elif data["status"] == "ACCEPTED":
                operation["status"] = "CAPTURED"
                if state["pending_operation"] == operation["operation_ref"]:
                    state["pending_operation"] = None
                key = data["occurrence_key"]
                state["occurrences"][key] = {"operation_ref": operation["operation_ref"], "ingestion_ref": data["ingestion_ref"], "capture_snapshot": data["capture_snapshot"]}
                anchor = data["anchor"]
                if operation["kind"] == "TASK":
                    active = state["active_attempt"]
                    if active is not None:
                        _close(state, state["attempts"][active], "SUPERSEDED_BEFORE_FOLLOWUP", seq)
                    ref = anchor["attempt_ref"]
                    state["attempts"][ref] = {**anchor, "operation_ref": operation["operation_ref"], "occurrence_key": key,
                        "logical_resource": operation["logical_resource"], "config_id": operation["config_id"],
                        "opened_sequence": seq, "closed_sequence": None, "close_reason": None,
                        "selected_followup": None, "flags": []}
                    state["active_attempt"] = ref
                else:
                    attempt = state["attempts"][operation["attempt_ref"]]
                    state["followups"][anchor["followup_ref"]] = {**anchor, "occurrence_key": key,
                        "operation_ref": operation["operation_ref"], "post_close_revision": operation["post_close_revision"]}
                    if not operation["post_close_revision"]:
                        attempt["selected_followup"] = anchor["followup_ref"]
                        _close(state, attempt, "FIRST_FOLLOWUP", seq)
            elif data["status"] not in ("WAIT", "DUPLICATE"):
                raise ContractError("controller: unknown observation result")
        elif kind == "INVOCATION_RECEIVED":
            state["invocations"][data["invocation_ref"]] = {**data, "stage": "RECEIVED", "history": ["RECEIVED"],
                "settled": False, "ever_published": False, "publication_unresolved": False}
        elif kind == "INVOCATION_STAGE":
            invocation = state["invocations"][data["invocation_ref"]]
            invocation["stage"] = data["stage"]
            invocation["history"].append(data["stage"])
            invocation["reason_flags"] = data.get("reason_flags", invocation.get("reason_flags", []))
            if "CONDITION_RESOURCE_CONFLICT" in data.get("reason_flags", []) and invocation["attempt_ref"] in state["attempts"]:
                state["attempts"][invocation["attempt_ref"]]["flags"].append("CONDITION_RESOURCE_CONFLICT")
            if data["stage"] == "PUBLISHED":
                invocation["ever_published"] = True
                state["publications"].setdefault(data["publication_ref"], data)
            if data["stage"] == "PUBLICATION_UNRESOLVED":
                invocation["publication_unresolved"] = True
            if data.get("settled", False):
                invocation["settled"] = True
        elif kind == "CLOSE":
            _close(state, state["attempts"][data["attempt_ref"]], data["reason"], seq)
        elif kind == "LATE_EVIDENCE":
            attempt = state["attempts"][data["attempt_ref"]]
            attempt["flags"].extend(["HOLD_LATE_EVIDENCE", "CLOSURE_UNRESOLVED"])
            state["stopped_flags"].append("HOLD_LATE_EVIDENCE")
        elif kind == "ANALYSIS":
            state["analyses"][data["analysis_ref"]] = data
        else:
            raise ContractError("controller: unknown command event")
    for attempt in state["attempts"].values():
        attempt["reason_flags"] = _flags(attempt, state)
        attempt["closure_status"] = ("OPEN" if attempt["closed_sequence"] is None else
            "CLOSURE_UNRESOLVED" if "CLOSURE_UNRESOLVED" in attempt["reason_flags"] or "HOLD_PUBLICATION_UNRESOLVED" in attempt["reason_flags"] else "CLOSED")
        attempt["single_invocation_interpretation"] = attempt["closure_status"] == "CLOSED" and not attempt["reason_flags"]
    state["stopped_flags"] = sorted(set(state["stopped_flags"]))
    state["counts"] = {name: len(state[name]) for name in ("opportunities", "operations", "ingestions", "occurrences", "attempts", "invocations", "publications", "followups", "analyses")}
    return freeze_json(state)
