"""Pure WSS V2 singleton join over a declared cohort; no archived D3 engine."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from itertools import islice
from typing import Any, Mapping, Iterable

from .outcomes import (Composite, ExternalRow, COMPOSITE_FIELDS, OutcomeRecipe,
                       read_analysis, exposure_metadata, selected_source, cpc_identifier)
from .primitives import (ContractError, canonical_json_bytes, freeze_json, plain_json,
                         require_identifier, require_digest)

_VERDICTS = {"ADMIT", "REJECT", "QUARANTINE", "ERROR_INPUT", "ERROR_CONFIG"}
_TERMINALS = ("ADMISSION_COMPOSITE_AMBIGUOUS", "EXTERNAL_COMPOSITE_AMBIGUOUS", "EXTERNAL_MISSING",
              "EXTERNAL_MEASURE_INVALID", "JOINED")


@dataclass(frozen=True, slots=True)
class CoreEntry:
    receipt_ref: str
    input_ref: str | None
    result: Mapping | None = field(repr=False)

    def __post_init__(self):
        require_identifier(self.receipt_ref, "receipt_ref")
        if self.result is None:
            if self.input_ref is not None:
                require_identifier(self.input_ref, "input_ref")
            return
        result = plain_json(self.result)
        expected = {"input_ref", "input_sha256", "case_id", "contract_version", "profile_id", "profile_version",
                    "disposition", "diagnostics", "admitted_record"}
        if (not isinstance(result, dict) or set(result) != expected or type(result["disposition"]) is not str
                or result["disposition"] not in _VERDICTS or result["input_ref"] != self.input_ref):
            raise ContractError("supplied core result shape/identity unsupported")
        require_identifier(self.input_ref, "input_ref")
        require_digest(result["input_sha256"], "input_sha256")
        if result["disposition"] == "ADMIT":
            record = result["admitted_record"]
            allowed = {*COMPOSITE_FIELDS, "input_ref", "case_id", "attributed_condition", "artifact_version"}
            if (not isinstance(record, dict) or set(record) != allowed or Composite.interpret(record) is None
                    or record.get("input_ref") != self.input_ref or record.get("case_id") != result["case_id"]):
                raise ContractError("admitted metadata/composite unavailable")
            for name in ("case_id", "attributed_condition", "artifact_version"):
                cpc_identifier(record[name], name)
            if any(d.get("disposition") in {"REJECT", "ERROR_INPUT", "QUARANTINE", "NOT_EVALUABLE", "ERROR_CONFIG"}
                   for d in result["diagnostics"]):
                raise ContractError("ADMIT contradicts supplied diagnostics")
        elif result["admitted_record"] is not None:
            raise ContractError("non-ADMIT cannot carry admitted metadata")
        object.__setattr__(self, "result", freeze_json(result))


def entries_from_adapter(view: Mapping) -> tuple[CoreEntry, ...]:
    """Consume actual WP06 retained/unresolved rows; never fabricate a verdict."""
    return tuple(CoreEntry(row["receipt_ref"], row["input_ref"], row["result"]) for row in view["rows"])


@dataclass(frozen=True, slots=True)
class JoinPolicy:
    rubric_id: str
    rubric_version: str
    recipe_digest: str

    def __post_init__(self):
        require_identifier(self.rubric_id, "rubric_id")
        require_identifier(self.rubric_version, "rubric_version")
        require_digest(self.recipe_digest, "recipe_digest")

    @classmethod
    def from_recipe(cls, recipe: OutcomeRecipe):
        return cls(recipe.data["rubric_id"], recipe.data["rubric_version"], recipe.digest)


@dataclass(frozen=True, slots=True)
class NativeMapping:
    status: str
    reason_flags: tuple[str, ...] = ()
    analysis_ref: str | None = None
    current_head: str | None = None

    def __post_init__(self):
        if type(self.status) is not str or self.status not in {"PENDING", "HOLD", "ELIGIBLE"}:
            raise ContractError("native mapping status unsupported")
        if type(self.reason_flags) not in (list, tuple):
            raise ContractError("native reason flags require list/tuple")
        flags = tuple(sorted(set(require_identifier(f, "reason_flag") for f in self.reason_flags)))
        if self.status == "ELIGIBLE" and flags:
            raise ContractError("eligible mapping cannot hide native reason flags")
        for value in (self.analysis_ref, self.current_head):
            if value is not None:
                require_identifier(value, "analysis ref")
        object.__setattr__(self, "reason_flags", flags)


def mapping_from_analysis(controller, analysis_reference, entry: CoreEntry, exposure_raw: bytes | None) -> NativeMapping:
    """Read only local frozen analysis; core validity and source truth are distinct.

    Publication/followup order uses controller sequence, not comparison of native
    second-resolution timestamps with CPC microsecond/observer clocks.
    """
    if entry.result is None or entry.result["disposition"] != "ADMIT":
        raise ContractError("native mapping is defined here only for ADMIT")
    basis = read_analysis(controller, analysis_reference)
    analysis_id = basis["document"]["analysis_ref"]
    def mapped(status, flags):
        return NativeMapping(status, tuple(flags), analysis_id, basis["current_head"])
    record = entry.result["admitted_record"]
    view = basis["view"]
    attempt = view["attempts"].get(record["unit_token"])
    if attempt is None:
        return mapped("HOLD", ["NATIVE_OCCURRENCE_UNAVAILABLE"])
    flags = set(attempt["reason_flags"]) | set(controller.context.readiness_issues())
    if exposure_raw is None:
        return mapped("PENDING", flags | {"FINAL_EXPOSURE_LINKAGE_PENDING"})
    try:
        exposure = exposure_metadata(exposure_raw)
    except ContractError:
        return mapped("HOLD", flags | {"FINAL_EXPOSURE_LINKAGE_INVALID"})
    payload = exposure["payload"]
    if (exposure["record_id"] != record["exposure_record_id"]
            or exposure["integrity"]["content_digest"] != record["exposure_digest"]
            or any(exposure[name] != record[name] for name in ("unit_token", "experiment_id", "experiment_version"))
            or payload["artifact_version"] != record["artifact_version"]
            or payload["enacted_condition"] != record["attributed_condition"]):
        flags.add("EXPOSURE_CORE_CONTEXT_CONFLICT")
    expected_condition = {"WSS-U01-HINT": "hint", "WSS-U01-ANSWER": "answer"}.get(attempt["logical_resource"])
    if payload["enacted_condition"] != expected_condition:
        flags.add("CONDITION_RESOURCE_CONFLICT")
    invocation = view["invocations"].get(payload["invocation_id"])
    if invocation is None or invocation["attempt_ref"] != record["unit_token"] or not invocation["ever_published"]:
        flags.add("PUBLICATION_LINKAGE_UNAVAILABLE")
    if attempt["selected_followup"] is not None:
        try:
            _, follow, _, _, _, _ = selected_source(controller, basis, record["unit_token"])
            op_sequences = [e["sequence"] for e in basis["events"] if e["event"] == "OPERATION"
                            and e["data"]["operation_ref"] == follow["operation_ref"]]
            publication_sequences = [e["sequence"] for e in basis["events"] if e["event"] == "INVOCATION_STAGE"
                and e["data"]["invocation_ref"] == payload["invocation_id"] and e["data"]["stage"] == "PUBLISHED"]
            if not op_sequences or not publication_sequences or min(publication_sequences) >= op_sequences[0]:
                flags.add("OUTCOME_BEFORE_EXPOSURE")
        except ContractError:
            flags.add("NATIVE_FOLLOWUP_LINKAGE_INVALID")
    if attempt["closed_sequence"] is None:
        return mapped("PENDING", flags | {"EPISODE_OPEN"})
    return mapped("HOLD", flags) if flags else mapped("ELIGIBLE", ())


def _value_flags(row: ExternalRow, policy: JoinPolicy) -> set[str]:
    flags = set()
    if not row.shape_valid:
        flags.add("EXTERNAL_ROW_SHAPE_INVALID")
    if row.measure_state != "VALID":
        flags.add("EXTERNAL_VALUE_MISSING" if row.measure_state == "MISSING" else "EXTERNAL_VALUE_INVALID")
    if row.scalar_type != "int" or type(row.integer_value) is not int or not 0 <= row.integer_value <= 4:
        flags.add("EXTERNAL_VALUE_TYPE_OR_RANGE_INVALID")
    if row.rubric_id != policy.rubric_id or row.rubric_version != policy.rubric_version:
        flags.add("EXTERNAL_RUBRIC_MISMATCH")
    if row.recipe_digest != policy.recipe_digest:
        flags.add("EXTERNAL_RECIPE_MISMATCH")
    if row.lineage_ref is None:
        flags.add("EXTERNAL_LINEAGE_MISSING")
    return flags


def analyze(entries: Iterable[CoreEntry], external_rows: Iterable[ExternalRow | Mapping],
            mappings: Mapping[str, NativeMapping], policy: JoinPolicy, *, cohort_ref: str,
            snapshot_ref: str) -> Mapping:
    """Pure all-row analysis. Inputs are supplied facts, never native authority.

    Persist the returned immutable object with explicit SnapshotStore.put if
    desired; this function reads/writes no files and calls no CPC/D3 engine.
    """
    require_identifier(cohort_ref, "cohort_ref")
    require_identifier(snapshot_ref, "snapshot_ref")
    core, external = tuple(islice(entries, 10001)), tuple(islice(external_rows, 10001))
    if len(core) > 10000 or len(external) > 10000 or type(policy) is not JoinPolicy:
        raise ContractError("join supplied cohort exceeds supported domain")
    if any(type(e) is not CoreEntry for e in core) or len({e.receipt_ref for e in core}) != len(core):
        raise ContractError("unique core receipt identities required")
    admitted = [e for e in core if e.result is not None and e.result["disposition"] == "ADMIT"]
    if set(mappings) - {e.receipt_ref for e in admitted} or any(type(v) is not NativeMapping for v in mappings.values()):
        raise ContractError("mapping outside declared cohort")
    external = tuple(row if type(row) is ExternalRow else ExternalRow.from_mapping(row) for row in external)
    effective = {e.receipt_ref: mappings.get(e.receipt_ref, NativeMapping("PENDING", ("NATIVE_MAPPING_NOT_SUPPLIED",)))
                 for e in admitted}
    # Cardinality must be counted BEFORE native eligibility or scalar filtering.
    admission_counts = Counter(Composite.interpret(e.result["admitted_record"]) for e in admitted)
    external_counts = Counter(row.composite for row in external if row.composite is not None)
    grouped = {}
    external_ledger = []
    for ordinal, row in enumerate(external):
        flags = _value_flags(row, policy)
        if row.composite is None:
            flags.add("EXTERNAL_COMPOSITE_UNINTERPRETABLE")
        else:
            grouped.setdefault(row.composite, []).append((row, flags))
        external_ledger.append({"ordinal": ordinal, "row_ref": row.row_ref,
            "composite": None if row.composite is None else row.composite.to_mapping(),
            "reason_flags": sorted(flags), "raw_typed_descriptor": row.descriptor})
    core_counts = {k: 0 for k in ("ADMIT", "REJECT", "QUARANTINE", "ERROR_INPUT", "NOT_EVALUATED_CONFIG")}
    native_counts = {k: 0 for k in ("PENDING", "HOLD", "ELIGIBLE")}
    eligible_counts = {k: 0 for k in _TERMINALS}
    ledger, unresolved = [], 0
    for e in core:
        if e.result is None:
            unresolved += 1
            ledger.append({"receipt_ref": e.receipt_ref, "input_ref": e.input_ref, "core_disposition": None,
                "primary_reason": "CORE_EVALUATION_UNRESOLVED", "reason_flags": ["CORE_EVALUATION_UNRESOLVED"], "value": None})
            continue
        disposition = e.result["disposition"]
        bucket = "NOT_EVALUATED_CONFIG" if disposition == "ERROR_CONFIG" else disposition
        core_counts[bucket] += 1
        if disposition != "ADMIT":
            reason = "NOT_EVALUATED_CONFIG" if disposition == "ERROR_CONFIG" else "CORE_" + disposition
            ledger.append({"receipt_ref": e.receipt_ref, "input_ref": e.input_ref, "core_disposition": disposition,
                "primary_reason": reason, "reason_flags": [reason], "value": None})
            continue
        composite = Composite.interpret(e.result["admitted_record"])
        mapping = effective[e.receipt_ref]
        native_counts[mapping.status] += 1
        flags = set(mapping.reason_flags)
        if mapping.status != "ELIGIBLE":
            flags.add("NATIVE_MAPPING_" + mapping.status)
        if admission_counts[composite] != 1:
            flags.add("ADMISSION_COMPOSITE_AMBIGUOUS")
        matches = grouped.get(composite, [])
        if len(matches) > 1:
            flags.add("EXTERNAL_COMPOSITE_AMBIGUOUS")
        if not matches:
            flags.add("EXTERNAL_MISSING")
        if any(f for _, f in matches):
            flags.add("EXTERNAL_MEASURE_INVALID")
            flags.update(f for _, reasons in matches for f in reasons)
        precedence = ("NATIVE_MAPPING_PENDING", "NATIVE_MAPPING_HOLD", *_TERMINALS[:-1])
        reason = next((r for r in precedence if r in flags), "JOINED")
        if mapping.status == "ELIGIBLE":
            eligible_counts[reason] += 1
        value = matches[0][0].integer_value if reason == "JOINED" else None
        ledger.append({"receipt_ref": e.receipt_ref, "input_ref": e.input_ref, "core_disposition": disposition,
            "composite": composite.to_mapping(), "mapping_status": mapping.status, "analysis_ref": mapping.analysis_ref,
            "current_head": mapping.current_head, "primary_reason": reason, "reason_flags": sorted(flags), "value": value,
            "admission_multiplicity": admission_counts[composite], "external_multiplicity": external_counts[composite]})
    if (len(core) != sum(core_counts.values()) + unresolved or core_counts["ADMIT"] != sum(native_counts.values())
            or native_counts["ELIGIBLE"] != sum(eligible_counts.values())):
        raise RuntimeError("join reconciliation failed")
    fresh = all(v.analysis_ref is not None and v.analysis_ref == v.current_head for v in effective.values())
    return freeze_json({"format": "wss-join-analysis-v1", "cohort_ref": cohort_ref, "snapshot_ref": snapshot_ref,
        "counts": {"received_core": len(core), "core_buckets": core_counts, "unresolved_core": unresolved,
            "admitted_mapping": native_counts, "eligible_terminals": eligible_counts,
            "external_received": len(external), "external_interpretable": sum(external_counts.values()),
            "external_uninterpretable": len(external) - sum(external_counts.values())},
        "accounting_equations_match": True, "complete_for_declared_snapshot": unresolved == 0 and native_counts["PENDING"] == 0 and fresh,
        "all_mappings_at_current_head": fresh,
        "core_ledger": ledger, "external_ledger": external_ledger,
        "Y_next": "NOT_MEASURED / NOT_VALIDATED_HERE", "scientific_JLA_sufficiency": "INSUFFICIENT_EVIDENCE_UNCHANGED"})
