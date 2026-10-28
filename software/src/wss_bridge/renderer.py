"""Pure finite-catalog renderer for WSS V2 R1–R5.

All inputs are explicit immutable values. No IO, authority lookup, CPC admission,
capture proof, clock, signing, publication, or learner-outcome call occurs here.
Opaque review/rights/resolution references are declarations, never permissions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from types import MappingProxyType
from typing import Any, Mapping

from .primitives import (
    ContractError, canonical_json_bytes, decode_json_object, freeze_json,
    require_digest, require_identifier, require_mapping, require_text,
)


PROMPT_FIELDS = (
    "prompt_format", "task_id", "task_version", "task_text", "task_span",
    "source_selection_ref", "source_excerpt", "help_request",
    "logical_resource_id", "catalog_version",
)
TASK_FIELDS = (
    "task_id", "task_version", "task_text", "task_span", "source_selection_ref",
    "source_excerpt", "help_request",
)
GENERATION_FIELDS = ("response_style", "max_output_chars", "include_rationale", "seed")
RESOURCES = MappingProxyType({"hint": "WSS-U01-HINT", "answer": "WSS-U01-ANSWER"})
JOINT_CONFIGS = MappingProxyType({
    "G_BASE": ("expanded", 1024, True, 0),
    "G_STYLE": ("compact", 1024, True, 0),
    "G_CAP": ("expanded", 640, True, 0),
    "G_RATIONALE": ("expanded", 1024, False, 0),
    "G_SEED": ("expanded", 1024, True, 1),
})
SLOT_BOUNDS = MappingProxyType({"C": (280, 360), "R": (160, 200), "E": (260, 300)})
TASK_SPAN_TOKEN = "{{task_span}}"
MAX_INPUT_BYTES = 1024 * 1024


class RendererError(ContractError):
    """Local pre-publication precondition error, never a core disposition."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _text(value: Any, name: str) -> str:
    return require_text(value, name, max_chars=MAX_INPUT_BYTES)


def _object_bytes(raw: bytes, name: str) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT_BYTES:
        raise RendererError(name + "_IMMUTABLE_BYTES_REQUIRED")
    return decode_json_object(raw, name)


def _canonical_object(raw: bytes, name: str) -> dict[str, Any]:
    row = _object_bytes(raw, name)
    if canonical_json_bytes(row) != raw:
        raise RendererError(name + "_NONCANONICAL")
    return row


def _bound_slot(template: str, span: str, slot: str) -> str:
    # Validate projected size BEFORE substitution can multiply two bounded raw
    # input lengths. Python integer arithmetic does not allocate the expansion.
    count = template.count(TASK_SPAN_TOKEN)
    length = len(template) + count * (len(span) - len(TASK_SPAN_TOKEN))
    low, high = SLOT_BOUNDS[slot]
    if not low <= length <= high:
        raise RendererError("CATALOG_POST_BINDING_SLOT_LENGTH")
    return template.replace(TASK_SPAN_TOKEN, span)


@dataclass(frozen=True)
class Generation:
    """Normalized consumed object. Construct once, then pass the same instance.

    Whitespace in configuration transport is immaterial; its normalized object
    bytes use the CPC sorted-key, compact, unescaped-Unicode JSON encoding.
    """

    response_style: str
    max_output_chars: int
    include_rationale: bool
    seed: int

    def __post_init__(self) -> None:
        if (type(self.response_style) is not str or type(self.max_output_chars) is not int
                or type(self.include_rationale) is not bool or type(self.seed) is not int):
            raise RendererError("GENERATION_FIELD_TYPE")
        if self.values not in JOINT_CONFIGS.values():
            raise RendererError("GENERATION_UNSUPPORTED_JOINT_TUPLE")

    @property
    def values(self) -> tuple[str, int, bool, int]:
        return self.response_style, self.max_output_chars, self.include_rationale, self.seed

    @property
    def config_id(self) -> str:
        return next(name for name, values in JOINT_CONFIGS.items() if values == self.values)

    def to_mapping(self) -> dict[str, Any]:
        return dict(zip(GENERATION_FIELDS, self.values))

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_mapping())

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Generation:
        row = require_mapping(value, "generation", required=GENERATION_FIELDS)
        return cls(**row)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Generation:
        return cls.from_mapping(_object_bytes(raw, "GENERATION"))


@dataclass(frozen=True)
class CatalogSnapshot:
    """One closed supplied snapshot; not evidence of pedagogical approval.

    Twelve slots are checked together, after the sole literal task-span token
    substitution. Other brace text is literal, never executed or interpreted.
    No learner text or unbounded query is substituted. All slot bytes are bound
    by the supplied canonical snapshot; no generated fallback content exists.
    """

    raw_bytes: bytes = field(repr=False)
    task: Mapping[str, str] = field(init=False, repr=False)
    conditions: Mapping[str, Any] = field(init=False, repr=False)
    catalog_version: str = field(init=False)
    evidence_class: str = field(init=False)
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        row = require_mapping(_canonical_object(self.raw_bytes, "CATALOG"), "catalog",
            required=("catalog_format", "catalog_version", "evidence_class", "task", "conditions"))
        if row["catalog_format"] != "wss-renderer-catalog-v1":
            raise RendererError("CATALOG_FORMAT")
        require_identifier(row["catalog_version"], "catalog_version")
        if row["evidence_class"] not in ("SYNTHETIC_OFFLINE_FIXTURE", "OWNER_SUPPLIED_CONTENT"):
            raise RendererError("CATALOG_EVIDENCE_CLASS")
        task = require_mapping(row["task"], "catalog.task", required=TASK_FIELDS)
        for name in TASK_FIELDS:
            _text(task[name], "catalog.task." + name)
        # Substituted source is data. Avoid recursive/ambiguous token expansion.
        if TASK_SPAN_TOKEN in task["task_span"]:
            raise RendererError("TASK_SPAN_RECURSIVE_TOKEN")
        conditions = require_mapping(row["conditions"], "conditions", required=RESOURCES)
        for condition, resource in RESOURCES.items():
            entry = require_mapping(conditions[condition], "condition",
                                    required=("logical_resource_id", "variants"))
            if entry["logical_resource_id"] != resource:
                raise RendererError("CATALOG_RESOURCE_CONDITION_MISMATCH")
            variants = require_mapping(entry["variants"], "variants", required=("A", "B"))
            bound_cores = []
            for variant in ("A", "B"):
                slots = require_mapping(variants[variant], "slots", required=SLOT_BOUNDS)
                for slot in SLOT_BOUNDS:
                    template = _text(slots[slot], "slot." + slot)
                    bound = _bound_slot(template, task["task_span"], slot)
                    if slot == "C":
                        if TASK_SPAN_TOKEN not in template:
                            raise RendererError("CATALOG_CORE_TASK_SPAN_TOKEN_REQUIRED")
                        bound_cores.append(bound.encode("utf-8"))
            if bound_cores[0] == bound_cores[1]:
                raise RendererError("CATALOG_SEED_CORES_IDENTICAL")
        object.__setattr__(self, "task", freeze_json(task))
        object.__setattr__(self, "conditions", freeze_json(conditions))
        object.__setattr__(self, "catalog_version", row["catalog_version"])
        object.__setattr__(self, "evidence_class", row["evidence_class"])
        object.__setattr__(self, "digest", _sha(self.raw_bytes))

    @classmethod
    def from_bytes(cls, raw: bytes) -> CatalogSnapshot:
        return cls(raw)


@dataclass(frozen=True)
class ResolutionBinding:
    """Externally supplied assignment/profile resolution, not self-authority.

    A dependent workflow must supply its actual authorized resolution. Matching
    arbitrary self-created digests/references cannot establish that authority.
    Native context is an opaque reference here, not a runtime verification.
    """

    resolution_ref: str
    context_ref: str
    task_id: str
    task_version: str
    task_span: str
    logical_resource_id: str
    condition: str
    config_id: str
    bundle_ref: str
    catalog_digest: str
    prompt_digest: str
    generation_digest: str
    content_review_ref: str | None
    internal_rights_ref: str | None

    def __post_init__(self) -> None:
        for name in ("resolution_ref", "context_ref", "task_id", "task_version",
                     "logical_resource_id", "bundle_ref"):
            require_identifier(getattr(self, name), name)
        _text(self.task_span, "binding.task_span")
        for name in ("catalog_digest", "prompt_digest", "generation_digest"):
            require_digest(getattr(self, name), name)
        require_identifier(self.condition, "condition")
        require_identifier(self.config_id, "config_id")
        if self.condition not in RESOURCES or self.logical_resource_id != RESOURCES[self.condition]:
            raise RendererError("RESOLUTION_RESOURCE_CONDITION_MISMATCH")
        if self.config_id not in JOINT_CONFIGS:
            raise RendererError("RESOLUTION_UNSUPPORTED_CONFIG")
        for name in ("content_review_ref", "internal_rights_ref"):
            if getattr(self, name) is not None:
                require_identifier(getattr(self, name), name)


@dataclass(frozen=True)
class RenderResult:
    body: bytes
    prompt_bytes: bytes = field(repr=False)
    generation: Generation = field(repr=False)
    catalog: CatalogSnapshot = field(repr=False)
    binding: ResolutionBinding = field(repr=False)
    trace: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "trace", freeze_json(self.trace))


def render(prompt_bytes: bytes, generation: Generation, catalog: CatalogSnapshot,
           binding: ResolutionBinding) -> RenderResult:
    """Validate, select and assemble only from the exact supplied objects.

    No invocation allocation or failure receipt is manufactured. WP03/caller
    allocates an invocation before calling; WP05 will own actual capture,
    commitment and publication. This result is a prepared body, not exposure.
    """
    # Exact local types avoid executing caller-defined Mapping/property hooks
    # in this pure consume boundary. Constructors copy/freeze external inputs.
    if (type(generation) is not Generation or type(catalog) is not CatalogSnapshot
            or type(binding) is not ResolutionBinding):
        raise RendererError("IMMUTABLE_RENDERER_INPUTS_REQUIRED")
    if binding.content_review_ref is None or binding.internal_rights_ref is None:
        raise RendererError("CONTENT_DECLARATIONS_PENDING")
    if catalog.digest != binding.catalog_digest:
        raise RendererError("CATALOG_NOT_BOUND")
    row = require_mapping(_canonical_object(prompt_bytes, "PROMPT"), "prompt", required=PROMPT_FIELDS)
    for name in PROMPT_FIELDS:
        _text(row[name], "prompt." + name)
    if row["prompt_format"] != "wss-prompt-v2":
        raise RendererError("PROMPT_FORMAT")
    if _sha(prompt_bytes) != binding.prompt_digest:
        raise RendererError("PROMPT_NOT_REGISTERED")
    if (row["catalog_version"] != catalog.catalog_version
            or any(row[name] != catalog.task[name] for name in TASK_FIELDS)):
        raise RendererError("PROMPT_CATALOG_TASK_SOURCE_MISMATCH")
    if (row["logical_resource_id"] != binding.logical_resource_id
            or any(row[name] != getattr(binding, name) for name in ("task_id", "task_version", "task_span"))):
        raise RendererError("PROMPT_RESOLUTION_MISMATCH")
    if generation.config_id != binding.config_id or _sha(generation.canonical_bytes) != binding.generation_digest:
        raise RendererError("GENERATION_NOT_REGISTERED")

    # Selection and exact substitution use the parsed supplied prompt, never a
    # global condition switch or a re-read pathname. Trusted binding cross-checks
    # the prompt selection; it cannot substitute a different condition/task.
    condition = next(name for name, resource in RESOURCES.items() if resource == row["logical_resource_id"])
    variant = "A" if generation.seed == 0 else "B"
    selected = catalog.conditions[condition]["variants"][variant]
    slots = {name: _bound_slot(selected[name], row["task_span"], name) for name in SLOT_BOUNDS}
    blocks = [slots["C"]]
    if generation.include_rationale:
        blocks.append(slots["R"])
    mandatory = "\n\n".join(blocks)
    if len(mandatory) > generation.max_output_chars:
        raise RendererError("MANDATORY_CONTENT_EXCEEDS_CAP")
    if generation.response_style == "compact":
        elaboration = "elaboration_not_requested_style"
    elif len(mandatory + "\n\n" + slots["E"]) <= generation.max_output_chars:
        blocks.append(slots["E"])
        elaboration = "elaboration_included"
    else:
        elaboration = "elaboration_omitted_budget"
    body_text = "\n\n".join(blocks)
    body = body_text.encode("utf-8")
    trace = {
        "renderer_version": "wss-finite-renderer-1.0",
        "status": "BODY_PREPARED_NOT_PUBLISHED",
        "evidence_class": catalog.evidence_class,
        "resolution_ref": binding.resolution_ref, "context_ref": binding.context_ref,
        "bundle_ref": binding.bundle_ref, "condition": condition,
        "logical_resource_id": row["logical_resource_id"], "config_id": generation.config_id,
        "task_id": row["task_id"], "task_version": row["task_version"], "task_span": row["task_span"],
        "source_selection_ref": row["source_selection_ref"], "catalog_version": row["catalog_version"],
        "variant": variant, "rationale_included": generation.include_rationale,
        "elaboration_decision": elaboration, "selected_slots": ["C"]
            + (["R"] if generation.include_rationale else [])
            + (["E"] if elaboration == "elaboration_included" else []),
        "slot_codepoints": {name: len(text) for name, text in slots.items()},
        "mandatory_codepoints": len(mandatory), "body_codepoints": len(body_text),
        "body_byte_length": len(body), "cap_codepoints": generation.max_output_chars,
        "prompt_digest": _sha(prompt_bytes), "generation_digest": _sha(generation.canonical_bytes),
        "catalog_digest": catalog.digest, "body_digest": _sha(body),
        "content_review_ref": binding.content_review_ref, "internal_rights_ref": binding.internal_rights_ref,
        "review_rights_refs_are_declarations_only": True,
        "independent_observer_or_actual_use_proof": False,
    }
    return RenderResult(body, prompt_bytes, generation, catalog, binding, trace)
