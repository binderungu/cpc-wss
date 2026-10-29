"""Offline, immutable native-source and ledger data contracts.

Parsing proves representational shape only. Binding diagnostics neither verify a
native source nor confer permission to read, submit, invoke, publish or evaluate.
No helper, controller, admission engine, IO or identity allocator lives here.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
from typing import Any, ClassVar, Mapping

from .primitives import (
    ContractError,
    freeze_json,
    optional_identifier,
    plain_json,
    require_bool,
    require_digest,
    require_identifier,
    require_int,
    require_mapping,
    require_rfc3339,
    require_text,
)


class NativeReadStatus(str, Enum):
    MATCH_OBSERVED = "MATCH_OBSERVED"
    NO_MATCH = "NO_MATCH"
    MULTIPLE_MATCH = "MULTIPLE_MATCH"
    READ_UNAVAILABLE = "READ_UNAVAILABLE"
    SOURCE_CONFLICT = "SOURCE_CONFLICT"
    NATIVE_RESULT_UNRESOLVED = "NATIVE_RESULT_UNRESOLVED"


class ObservationRelation(str, Enum):
    DUPLICATE_OBSERVATION = "DUPLICATE_OBSERVATION"
    NEW_OCCURRENCE = "NEW_OCCURRENCE"
    SOURCE_CONFLICT = "SOURCE_CONFLICT"
    IDENTITY_UNRESOLVED = "IDENTITY_UNRESOLVED"


class CoreDisposition(str, Enum):
    ADMIT = "ADMIT"
    REJECT = "REJECT"
    QUARANTINE = "QUARANTINE"
    ERROR_INPUT = "ERROR_INPUT"


class EvaluationState(str, Enum):
    COMPLETED = "COMPLETED"
    NOT_EVALUATED_CONFIG = "NOT_EVALUATED_CONFIG"
    API_FAILURE = "API_FAILURE"
    PENDING = "PENDING"


class MappingStatus(str, Enum):
    PENDING = "PENDING"
    HOLD = "HOLD"
    ELIGIBLE = "ELIGIBLE"


class RecordKind(str, Enum):
    OPPORTUNITY = "OPPORTUNITY"
    SUBMIT_OPERATION = "SUBMIT_OPERATION"
    NATIVE_OBSERVATION = "NATIVE_OBSERVATION"
    ATTEMPT_REFERENCE = "ATTEMPT_REFERENCE"
    INVOCATION_REFERENCE = "INVOCATION_REFERENCE"
    PUBLICATION_REFERENCE = "PUBLICATION_REFERENCE"
    FOLLOWUP_REFERENCE = "FOLLOWUP_REFERENCE"
    CORE_INPUT_REFERENCE = "CORE_INPUT_REFERENCE"
    CORE_RESULT_REFERENCE = "CORE_RESULT_REFERENCE"
    MAPPING_ASSESSMENT = "MAPPING_ASSESSMENT"
    EXTERNAL_ROW_REFERENCE = "EXTERNAL_ROW_REFERENCE"
    JOIN_ASSESSMENT = "JOIN_ASSESSMENT"
    ANALYSIS_SNAPSHOT_REFERENCE = "ANALYSIS_SNAPSHOT_REFERENCE"
    FAILURE = "FAILURE"
    AUDIT_REFERENCE = "AUDIT_REFERENCE"


def _enum(enum_type: type[Enum], value: Any, field: str) -> Enum:
    if isinstance(value, enum_type):
        return value
    require_text(value, field)
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(f"{field}: unsupported value") from exc


def _optional_int(value: Any, field: str) -> int | None:
    return None if value is None else require_int(value, field, minimum=0)


def _optional_text(value: Any, field: str, *, allow_empty: bool = False) -> str | None:
    return None if value is None else require_text(value, field, allow_empty=allow_empty)


def _optional_digest(value: Any, field: str) -> str | None:
    return None if value is None else require_digest(value, field)


def _optional_time(value: Any, field: str) -> str | None:
    return None if value is None else require_rfc3339(value, field)


def _optional_bool(value: Any, field: str) -> bool | None:
    return None if value is None else require_bool(value, field)


def _flags(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ContractError(f"{field}: expected an array")
    return tuple(require_identifier(item, f"{field}[{index}]") for index, item in enumerate(value))


class _FlatContract:
    """Nullable observed fields are absent facts, never inferred zero values."""

    _validators: ClassVar[Mapping[str, Any]] = {}

    def __post_init__(self) -> None:
        for field, validator in self._validators.items():
            object.__setattr__(self, field, validator(getattr(self, field), field))

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> Any:
        names = tuple(field.name for field in fields(cls))
        supplied = require_mapping(data, cls.__name__, optional=names)
        return cls(**supplied)

    def to_mapping(self) -> dict[str, Any]:
        return {field.name: getattr(self, field.name) for field in fields(self)}


@dataclass(frozen=True)
class SourceIdentity(_FlatContract):
    source_epoch_ref: str | None = None
    instance_ref: str | None = None
    source_version_ref: str | None = None
    runtime_version_ref: str | None = None

    _validators = dict.fromkeys(
        ("source_epoch_ref", "instance_ref", "source_version_ref", "runtime_version_ref"),
        optional_identifier,
    )


@dataclass(frozen=True)
class ActorBinding(_FlatContract):
    actor_ref: str | None = None
    registry_ref: str | None = None
    expected_userid: int | None = None

    _validators = {
        "actor_ref": optional_identifier,
        "registry_ref": optional_identifier,
        "expected_userid": _optional_int,
    }


@dataclass(frozen=True)
class NativeTarget(_FlatContract):
    """Declared comparison target; its presence is not operator approval."""

    target_ref: str | None = None
    source_epoch_ref: str | None = None
    courseid: int | None = None
    feedback_route: str | None = None
    response_scope_courseid: int | None = None
    cmid: int | None = None
    feedback_id: int | None = None
    item_id: int | None = None
    contextid: int | None = None
    contextlevel: int | None = None
    eventname: str | None = None
    objecttable: str | None = None
    item_type: str | None = None
    item_digest: str | None = None
    item_presentation_digest: str | None = None
    controlled_value_digest: str | None = None

    _validators = {
        **dict.fromkeys(("target_ref", "source_epoch_ref"), optional_identifier),
        **dict.fromkeys(("courseid", "response_scope_courseid", "cmid", "feedback_id", "item_id", "contextid", "contextlevel"), _optional_int),
        **dict.fromkeys(("feedback_route", "eventname", "objecttable", "item_type"), _optional_text),
        **dict.fromkeys(("item_digest", "item_presentation_digest", "controlled_value_digest"), _optional_digest),
    }


@dataclass(frozen=True)
class NativeOccurrence(_FlatContract):
    """One actually reported standard-log row, not a completed entity."""

    standard_log_record_id: int | None = None
    eventname: str | None = None
    objecttable: str | None = None
    objectid: int | None = None
    contextid: int | None = None
    contextlevel: int | None = None
    contextinstanceid: int | None = None
    courseid: int | None = None
    userid: int | None = None
    relateduserid: int | None = None
    realuserid: int | None = None
    realuserid_observed: bool | None = None
    origin: str | None = None
    other_cmid: int | None = None
    other_instanceid: int | None = None
    anonymous: bool | None = None
    other_anonymous: bool | None = None
    native_time: str | None = None

    _validators = {
        **dict.fromkeys(("standard_log_record_id", "objectid", "contextid", "contextlevel", "contextinstanceid", "courseid", "userid", "relateduserid", "realuserid", "other_cmid", "other_instanceid"), _optional_int),
        **dict.fromkeys(("eventname", "objecttable", "origin"), _optional_text),
        **dict.fromkeys(("realuserid_observed", "anonymous", "other_anonymous"), _optional_bool),
        "native_time": _optional_time,
    }


@dataclass(frozen=True)
class NativeValueSnapshot(_FlatContract):
    """Exact source locators/digests; protected bytes remain at restricted refs."""

    snapshot_ref: str | None = None
    completed_id: int | None = None
    completed_feedback_id: int | None = None
    completed_userid: int | None = None
    completed_anonymous: bool | None = None
    completed_courseid: int | None = None
    completed_modified_time: str | None = None
    item_id: int | None = None
    item_feedback_id: int | None = None
    item_type: str | None = None
    item_text_ref: str | None = None
    item_digest: str | None = None
    item_presentation_ref: str | None = None
    item_presentation_digest: str | None = None
    value_id: int | None = None
    value_completed_id: int | None = None
    value_item_id: int | None = None
    value_courseid: int | None = None
    value_bytes_ref: str | None = None
    value_digest: str | None = None

    _validators = {
        **dict.fromkeys(("snapshot_ref", "item_text_ref", "item_presentation_ref", "value_bytes_ref"), optional_identifier),
        **dict.fromkeys(("completed_id", "completed_feedback_id", "completed_userid", "completed_courseid", "item_id", "item_feedback_id", "value_id", "value_completed_id", "value_item_id", "value_courseid"), _optional_int),
        "completed_anonymous": _optional_bool,
        "completed_modified_time": _optional_time,
        "item_type": _optional_text,
        **dict.fromkeys(("item_digest", "item_presentation_digest", "value_digest"), _optional_digest),
    }


@dataclass(frozen=True)
class NativeReadReceipt:
    observation_ref: str
    operation_ref: str
    status: NativeReadStatus
    observer_time: str
    observer_sequence: int
    source: SourceIdentity | None = None
    target: NativeTarget | None = None
    actor: ActorBinding | None = None
    occurrences: tuple[NativeOccurrence, ...] = ()
    snapshots: tuple[NativeValueSnapshot, ...] = ()
    read_context_ref: str | None = None
    transaction_ref: str | None = None
    connection_ref: str | None = None
    consistent_snapshot_observed: bool | None = None
    target_course_category: int | None = None
    target_window_before_ref: str | None = None
    target_window_after_ref: str | None = None
    log_watermark: int | None = None
    cursor_end: int | None = None
    clean_interval_evidence_ref: str | None = None
    prior_operations_evidence_ref: str | None = None
    sole_writer_evidence_ref: str | None = None
    native_result_known: bool | None = None
    diagnostics: tuple[str, ...] = ()
    native_lira_event_id: None = None

    def __post_init__(self) -> None:
        for field in ("observation_ref", "operation_ref"):
            object.__setattr__(self, field, require_identifier(getattr(self, field), field))
        object.__setattr__(self, "status", _enum(NativeReadStatus, self.status, "status"))
        object.__setattr__(self, "observer_time", require_rfc3339(self.observer_time, "observer_time"))
        object.__setattr__(self, "observer_sequence", require_int(self.observer_sequence, "observer_sequence", minimum=0))
        for field, cls in (("source", SourceIdentity), ("target", NativeTarget), ("actor", ActorBinding)):
            value = getattr(self, field)
            if value is not None and not isinstance(value, cls):
                raise ContractError(f"{field}: expected {cls.__name__} or null")
        for field, cls in (("occurrences", NativeOccurrence), ("snapshots", NativeValueSnapshot)):
            value = getattr(self, field)
            if not isinstance(value, (tuple, list)) or any(not isinstance(item, cls) for item in value):
                raise ContractError(f"{field}: expected array of {cls.__name__}")
            object.__setattr__(self, field, tuple(value))
        for field in ("read_context_ref", "transaction_ref", "connection_ref", "target_window_before_ref", "target_window_after_ref", "clean_interval_evidence_ref", "prior_operations_evidence_ref", "sole_writer_evidence_ref"):
            object.__setattr__(self, field, optional_identifier(getattr(self, field), field))
        for field in ("consistent_snapshot_observed", "native_result_known"):
            object.__setattr__(self, field, _optional_bool(getattr(self, field), field))
        for field in ("log_watermark", "cursor_end", "target_course_category"):
            value = getattr(self, field)
            object.__setattr__(self, field, None if value is None else require_int(value, field, minimum=0))
        object.__setattr__(self, "diagnostics", _flags(self.diagnostics, "diagnostics"))
        if self.native_lira_event_id is not None:
            raise ContractError("native_lira_event_id: selected route requires null")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> NativeReadReceipt:
        required = ("observation_ref", "operation_ref", "status", "observer_time", "observer_sequence")
        optional = tuple(field.name for field in fields(cls) if field.name not in required)
        supplied = dict(require_mapping(data, "NativeReadReceipt", required=required, optional=optional))
        for name, nested_cls in (("source", SourceIdentity), ("target", NativeTarget), ("actor", ActorBinding)):
            if supplied.get(name) is not None:
                supplied[name] = nested_cls.from_mapping(supplied[name])
        for name, nested_cls in (("occurrences", NativeOccurrence), ("snapshots", NativeValueSnapshot)):
            value = supplied.get(name, ())
            if not isinstance(value, (list, tuple)):
                raise ContractError(f"{name}: expected an array")
            supplied[name] = tuple(nested_cls.from_mapping(item) for item in value)
        return cls(**supplied)

    def to_mapping(self) -> dict[str, Any]:
        result = {field.name: getattr(self, field.name) for field in fields(self)}
        result["status"] = self.status.value
        for name in ("source", "target", "actor"):
            value = getattr(self, name)
            result[name] = None if value is None else value.to_mapping()
        for name in ("occurrences", "snapshots"):
            result[name] = [item.to_mapping() for item in getattr(self, name)]
        result["diagnostics"] = list(self.diagnostics)
        return result

    def binding_issues(self) -> tuple[str, ...]:
        """Report missing/conflicting claims without changing status or source rows."""
        issues = list(self.diagnostics)

        def add(code: str) -> None:
            if code not in issues:
                issues.append(code)

        def compare(expected: Any, observed: Any, label: str) -> None:
            if expected is None or observed is None:
                add(f"{label}_UNRESOLVED")
            elif expected != observed:
                add(f"{label}_CONFLICT")

        if self.status is not NativeReadStatus.MATCH_OBSERVED:
            add(self.status.value)
        if self.native_result_known is not True:
            add("NATIVE_RESULT_UNRESOLVED")
        if self.consistent_snapshot_observed is not True:
            add("CONSISTENT_SNAPSHOT_UNVERIFIED")
        if self.clean_interval_evidence_ref is None and self.prior_operations_evidence_ref is None:
            add("CLEAN_INTERVAL_UNVERIFIED")
        if self.sole_writer_evidence_ref is None:
            add("SOLE_WRITER_UNVERIFIED")
        for field in ("read_context_ref", "transaction_ref", "connection_ref", "target_window_before_ref", "target_window_after_ref", "log_watermark", "cursor_end"):
            if getattr(self, field) is None:
                add(f"{field.upper()}_MISSING")
        if self.log_watermark is not None and self.cursor_end is not None and self.cursor_end < self.log_watermark:
            add("CURSOR_WINDOW_CONFLICT")
        if self.source is None:
            add("SOURCE_IDENTITY_UNRESOLVED")
        else:
            for field in ("source_epoch_ref", "instance_ref", "source_version_ref", "runtime_version_ref"):
                if getattr(self.source, field) is None:
                    add(f"{field.upper()}_MISSING")
        if self.target is None:
            add("TARGET_BINDING_UNRESOLVED")
        else:
            if self.target.target_ref is None:
                add("TARGET_REF_MISSING")
            if any(getattr(self.target, field) == 0 for field in ("courseid", "cmid", "feedback_id", "item_id", "contextid", "contextlevel")):
                add("TARGET_ZERO_ID")
            if self.target.feedback_route is None:
                add("FEEDBACK_ROUTE_UNRESOLVED")
            elif self.target.feedback_route != "ordinary_course":
                add("UNSUPPORTED_FEEDBACK_ROUTE")
            if self.target.response_scope_courseid is None:
                add("RESPONSE_SCOPE_UNRESOLVED")
            elif self.target.response_scope_courseid != 0:
                add("UNSUPPORTED_RESPONSE_SCOPE")
        if self.target_course_category is None:
            add("TARGET_COURSE_CATEGORY_UNRESOLVED")
        elif self.target_course_category == 0:
            add("UNSUPPORTED_SITE_FEEDBACK")
        if self.actor is None or self.actor.actor_ref is None or self.actor.registry_ref is None or self.actor.expected_userid is None:
            add("ACTOR_REGISTRY_UNRESOLVED")
        if self.actor is not None and self.actor.expected_userid == 0:
            add("ACTOR_REGISTRY_ZERO_ID")
        if self.source is not None and self.target is not None:
            compare(self.target.source_epoch_ref, self.source.source_epoch_ref, "SOURCE_EPOCH")
        if len(self.occurrences) != 1:
            add("NATIVE_OCCURRENCE_UNAVAILABLE" if not self.occurrences else "NATIVE_OCCURRENCE_AMBIGUOUS")
        if len(self.snapshots) != 1:
            add("SOURCE_SNAPSHOT_UNAVAILABLE" if not self.snapshots else "SOURCE_SNAPSHOT_AMBIGUOUS")
        for occurrence in self.occurrences:
            if any(getattr(occurrence, field) == 0 for field in ("standard_log_record_id", "objectid", "contextid", "contextlevel", "contextinstanceid", "courseid", "userid", "relateduserid", "other_cmid", "other_instanceid")):
                add("SOURCE_ZERO_ID_REPORTED")
            if occurrence.standard_log_record_id is None:
                add("NATIVE_OCCURRENCE_ID_MISSING")
            if occurrence.native_time is None:
                add("NATIVE_TIME_MISSING")
            if occurrence.origin is None:
                add("NATIVE_ORIGIN_MISSING")
            if occurrence.standard_log_record_id is not None and self.log_watermark is not None and occurrence.standard_log_record_id <= self.log_watermark:
                add("OCCURRENCE_OUTSIDE_WATERMARK")
            if occurrence.standard_log_record_id is not None and self.cursor_end is not None and occurrence.standard_log_record_id > self.cursor_end:
                add("OCCURRENCE_OUTSIDE_CURSOR_END")
            if occurrence.realuserid_observed is not True:
                add("NO_IMPERSONATION_UNVERIFIED")
            if occurrence.realuserid == 0:
                add("REALUSERID_BINDING_UNRESOLVED")
            elif occurrence.realuserid is not None:
                add("IMPERSONATION_REPORTED")
            if occurrence.anonymous is not False:
                add("EVENT_ANONYMITY_UNRESOLVED" if occurrence.anonymous is None else "ANONYMOUS_ROUTE_CONFLICT")
            if occurrence.other_anonymous is not False:
                add("OTHER_ANONYMITY_UNRESOLVED" if occurrence.other_anonymous is None else "ANONYMOUS_ROUTE_CONFLICT")
            if self.actor is not None:
                compare(self.actor.expected_userid, occurrence.userid, "INITIATING_ACTOR")
                compare(self.actor.expected_userid, occurrence.relateduserid, "RESPONSE_OWNER")
            if self.target is not None:
                for target_field, event_field, label in (("courseid", "courseid", "EVENT_COURSE"), ("cmid", "contextinstanceid", "EVENT_CONTEXT_INSTANCE"), ("cmid", "other_cmid", "EVENT_CMID"), ("feedback_id", "other_instanceid", "EVENT_FEEDBACK"), ("contextid", "contextid", "EVENT_CONTEXT"), ("contextlevel", "contextlevel", "EVENT_CONTEXT_LEVEL"), ("eventname", "eventname", "EVENT_NAME"), ("objecttable", "objecttable", "EVENT_OBJECT_TABLE")):
                    compare(getattr(self.target, target_field), getattr(occurrence, event_field), label)
        for snapshot in self.snapshots:
            if any(getattr(snapshot, field) == 0 for field in ("completed_id", "completed_feedback_id", "completed_userid", "item_id", "item_feedback_id", "value_id", "value_completed_id", "value_item_id")):
                add("SOURCE_ZERO_ID_REPORTED")
            for field in ("snapshot_ref", "completed_modified_time", "item_type", "item_text_ref", "item_digest", "item_presentation_ref", "item_presentation_digest", "value_id", "value_bytes_ref", "value_digest"):
                if getattr(snapshot, field) is None:
                    add(f"{field.upper()}_MISSING")
            if snapshot.completed_anonymous is not False:
                add("COMPLETED_ANONYMITY_UNRESOLVED" if snapshot.completed_anonymous is None else "ANONYMOUS_ROUTE_CONFLICT")
            compare(snapshot.completed_id, snapshot.value_completed_id, "VALUE_COMPLETED")
            compare(snapshot.item_id, snapshot.value_item_id, "VALUE_ITEM")
            if self.actor is not None:
                compare(self.actor.expected_userid, snapshot.completed_userid, "COMPLETED_OWNER")
            if self.target is not None:
                for target_field, snapshot_field, label in (("feedback_id", "completed_feedback_id", "COMPLETED_FEEDBACK"), ("feedback_id", "item_feedback_id", "ITEM_FEEDBACK"), ("response_scope_courseid", "completed_courseid", "COMPLETED_RESPONSE_SCOPE"), ("response_scope_courseid", "value_courseid", "VALUE_RESPONSE_SCOPE"), ("item_id", "item_id", "SOURCE_ITEM"), ("item_type", "item_type", "ITEM_TYPE"), ("item_digest", "item_digest", "ITEM_CONTENT"), ("item_presentation_digest", "item_presentation_digest", "ITEM_PRESENTATION"), ("controlled_value_digest", "value_digest", "SOURCE_VALUE")):
                    compare(getattr(self.target, target_field), getattr(snapshot, snapshot_field), label)
            for occurrence in self.occurrences:
                compare(occurrence.objectid, snapshot.completed_id, "EVENT_COMPLETED")
        return tuple(issues)


def classify_observations(previous: NativeReadReceipt, incoming: NativeReadReceipt) -> ObservationRelation:
    """Compare reported identity/content only; allocate no IDs, attempts or states.

    The content projection excludes receipt refs, observation clocks/sequences,
    controller context, snapshot refs and protected content locators. It retains
    exact native fields and source-content digests. A changed locator alone does
    not manufacture a new native occurrence or a payload conflict.
    """
    def identity(receipt: NativeReadReceipt) -> tuple[str, int] | None:
        if receipt.source is None or receipt.source.source_epoch_ref is None or len(receipt.occurrences) != 1:
            return None
        log_id = receipt.occurrences[0].standard_log_record_id
        # Retain a reported zero in the receipt, but never use it as a native
        # standard-log row identity. Booleans are excluded defensively too.
        return None if type(log_id) is not int or log_id <= 0 else (receipt.source.source_epoch_ref, log_id)

    previous_id, incoming_id = identity(previous), identity(incoming)
    if previous_id is None or incoming_id is None:
        return ObservationRelation.IDENTITY_UNRESOLVED
    if previous_id != incoming_id:
        return ObservationRelation.NEW_OCCURRENCE

    def known_conflict(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
        return any(
            left[key] is not None and right[key] is not None and left[key] != right[key]
            for key in left
        )

    # Retain a conflict already observable in partial receipts. Missing data
    # alone is unresolved, rather than an asserted disagreement with a value.
    if known_conflict(previous.source.to_mapping(), incoming.source.to_mapping()):
        return ObservationRelation.SOURCE_CONFLICT
    if known_conflict({"category": previous.target_course_category}, {"category": incoming.target_course_category}):
        return ObservationRelation.SOURCE_CONFLICT
    if known_conflict(previous.occurrences[0].to_mapping(), incoming.occurrences[0].to_mapping()):
        return ObservationRelation.SOURCE_CONFLICT
    if len(previous.snapshots) == 1 and len(incoming.snapshots) == 1:
        left_snapshot = previous.snapshots[0].to_mapping()
        right_snapshot = incoming.snapshots[0].to_mapping()
        for field in ("snapshot_ref", "item_text_ref", "item_presentation_ref", "value_bytes_ref"):
            left_snapshot.pop(field)
            right_snapshot.pop(field)
        if known_conflict(left_snapshot, right_snapshot):
            return ObservationRelation.SOURCE_CONFLICT

    def content(receipt: NativeReadReceipt) -> Any:
        if len(receipt.snapshots) != 1 or receipt.target_course_category is None:
            return None
        snapshot = receipt.snapshots[0].to_mapping()
        required = ("snapshot_ref", "completed_id", "item_id", "value_id", "value_completed_id", "value_item_id", "value_digest", "item_digest", "item_presentation_digest")
        if any(snapshot[field] is None for field in required):
            return None
        for field in ("snapshot_ref", "item_text_ref", "item_presentation_ref", "value_bytes_ref"):
            snapshot.pop(field)
        return freeze_json({
            "source": receipt.source.to_mapping(),
            "target_course_category": receipt.target_course_category,
            "occurrence": receipt.occurrences[0].to_mapping(),
            "snapshot": snapshot,
        })

    old_content, new_content = content(previous), content(incoming)
    if old_content is None or new_content is None:
        return ObservationRelation.IDENTITY_UNRESOLVED
    if old_content != new_content:
        return ObservationRelation.IDENTITY_UNRESOLVED
    return ObservationRelation.DUPLICATE_OBSERVATION


# These identify the grain of a record, not a transition policy or eligibility.
_PAYLOAD_REQUIRED = {
    RecordKind.OPPORTUNITY: ("opportunity_ref", "actor_ref", "target_ref", "status"),
    RecordKind.SUBMIT_OPERATION: ("operation_ref", "actor_ref", "target_ref", "status"),
    RecordKind.ATTEMPT_REFERENCE: ("attempt_ref", "occurrence_ref", "status"),
    RecordKind.INVOCATION_REFERENCE: ("invocation_ref", "attempt_ref", "status"),
    RecordKind.PUBLICATION_REFERENCE: ("publication_ref", "invocation_ref", "status"),
    RecordKind.FOLLOWUP_REFERENCE: ("followup_ref", "attempt_ref", "occurrence_ref", "status"),
    RecordKind.CORE_INPUT_REFERENCE: ("input_ref", "invocation_ref", "status"),
    RecordKind.CORE_RESULT_REFERENCE: ("input_ref", "evaluation_state", "disposition"),
    RecordKind.MAPPING_ASSESSMENT: ("input_ref", "mapping_status", "reason_flags"),
    RecordKind.EXTERNAL_ROW_REFERENCE: ("row_ref", "attempt_ref", "status"),
    RecordKind.JOIN_ASSESSMENT: ("input_ref", "terminal_reason", "reason_flags"),
    RecordKind.ANALYSIS_SNAPSHOT_REFERENCE: ("snapshot_ref", "status"),
    RecordKind.FAILURE: ("operation_ref", "layer", "status", "code"),
    RecordKind.AUDIT_REFERENCE: ("audit_ref", "status"),
}


# Exact entity identity at each record grain. A record's own record_ref names
# the history entry; entity_ref names the entity described by that entry.
_ENTITY_PAYLOAD_REF = {
    RecordKind.OPPORTUNITY: "opportunity_ref",
    RecordKind.SUBMIT_OPERATION: "operation_ref",
    RecordKind.NATIVE_OBSERVATION: "observation_ref",
    RecordKind.ATTEMPT_REFERENCE: "attempt_ref",
    RecordKind.INVOCATION_REFERENCE: "invocation_ref",
    RecordKind.PUBLICATION_REFERENCE: "publication_ref",
    RecordKind.FOLLOWUP_REFERENCE: "followup_ref",
    RecordKind.CORE_INPUT_REFERENCE: "input_ref",
    RecordKind.CORE_RESULT_REFERENCE: "input_ref",
    RecordKind.MAPPING_ASSESSMENT: "input_ref",
    RecordKind.EXTERNAL_ROW_REFERENCE: "row_ref",
    RecordKind.JOIN_ASSESSMENT: "input_ref",
    RecordKind.ANALYSIS_SNAPSHOT_REFERENCE: "snapshot_ref",
    RecordKind.FAILURE: "operation_ref",
    RecordKind.AUDIT_REFERENCE: "audit_ref",
}


@dataclass(frozen=True)
class LedgerRecord:
    """Immutable reference/history container, with no state-machine authority."""

    record_ref: str
    kind: RecordKind
    entity_ref: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "record_ref", require_identifier(self.record_ref, "record_ref"))
        object.__setattr__(self, "entity_ref", require_identifier(self.entity_ref, "entity_ref"))
        kind = _enum(RecordKind, self.kind, "kind")
        object.__setattr__(self, "kind", kind)
        if not isinstance(self.payload, Mapping):
            raise ContractError("payload: expected an object")
        payload = dict(self.payload)
        if kind is RecordKind.NATIVE_OBSERVATION:
            payload = NativeReadReceipt.from_mapping(payload).to_mapping()
        else:
            for field in _PAYLOAD_REQUIRED[kind]:
                if field not in payload:
                    raise ContractError(f"payload.{field}: required")
            for field, value in payload.items():
                if not isinstance(field, str):
                    raise ContractError("payload: keys must be strings")
                if field.endswith("_ref"):
                    # A present reference is exact; absent optional refs use null.
                    optional_identifier(value, f"payload.{field}")
                if field in _PAYLOAD_REQUIRED[kind] and field.endswith("_ref"):
                    require_identifier(value, f"payload.{field}")
            for field in ("status", "layer", "code", "terminal_reason"):
                if field in payload:
                    require_identifier(payload[field], f"payload.{field}")
            if "reason_flags" in payload:
                payload["reason_flags"] = _flags(payload["reason_flags"], "payload.reason_flags")
            if kind is RecordKind.CORE_RESULT_REFERENCE:
                state = _enum(EvaluationState, payload["evaluation_state"], "payload.evaluation_state")
                payload["evaluation_state"] = state.value
                if state is EvaluationState.COMPLETED:
                    payload["disposition"] = _enum(CoreDisposition, payload["disposition"], "payload.disposition").value
                elif payload["disposition"] is not None:
                    raise ContractError("payload.disposition: unevaluated refs require null")
                if state in (EvaluationState.NOT_EVALUATED_CONFIG, EvaluationState.API_FAILURE):
                    require_identifier(payload.get("error_ref"), "payload.error_ref")
            if kind is RecordKind.MAPPING_ASSESSMENT:
                payload["mapping_status"] = _enum(MappingStatus, payload["mapping_status"], "payload.mapping_status").value
            if "native_lira_event_id" in payload and payload["native_lira_event_id"] is not None:
                raise ContractError("payload.native_lira_event_id: selected route requires null")
        primary_ref = _ENTITY_PAYLOAD_REF[kind]
        if self.entity_ref != payload[primary_ref]:
            raise ContractError(f"entity_ref: must equal payload.{primary_ref}")
        object.__setattr__(self, "payload", freeze_json(payload, "payload"))

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> LedgerRecord:
        supplied = require_mapping(data, "LedgerRecord", required=("record_ref", "kind", "entity_ref", "payload"))
        return cls(**supplied)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "record_ref": self.record_ref,
            "kind": self.kind.value,
            "entity_ref": self.entity_ref,
            "payload": plain_json(self.payload),
        }
