"""One-invocation offline WP05 producer with explicit local-file publication.

Fixture-only HMAC custody and cooperative POSIX files, never a production trust
service or native access path. WP06 admission and downstream outcomes are absent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import importlib.util
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
import sys

from .capture import LocalClock, ClockObservation, capture_and_render, instant, new_ref, save, sha
from .configuration import verify_pinned_references
from .controller import OfflineController
from .ledger import SnapshotReference, SnapshotStore, _new_file, _fsync_directory, _real_directory, _read_file
from .primitives import (ContractError, canonical_json_bytes, decode_json_object,
                         freeze_json, plain_json, require_identifier, require_mapping, require_digest)
from .renderer import CatalogSnapshot, ResolutionBinding, RendererError, JOINT_CONFIGS, RESOURCES
from .producer_references import IndexedSnapshotStore, ProducerReferenceIndex


class ProducerError(ContractError):
    """Precondition/failure code, never a CPC admission disposition."""


_SAFE_CODES = frozenset({
    "TYPED_PRODUCER_INPUT_REQUIRED", "OBSERVER_CLOCK_CONTEXT_MISMATCH", "USE_BEFORE_RESOLUTION",
    "ACTUAL_CAPTURE_REGISTRY_MISMATCH", "PREPUBLICATION_PERSISTED_BYTES_MISMATCH",
    "RELEASE_ORDER_NOT_ESTABLISHED", "PUBLISHED_RESPONSE_READBACK_MISMATCH", "EXPOSURE_BEFORE_RELEASE",
    "POLICY_WINDOW_INACTIVE", "RESOLUTION_RAW_BYTES_REQUIRED", "SIGNED_OBJECT_SCHEMA_INVALID",
    "RESOLUTION_INTEGRITY_INVALID", "RESOLUTION_CONTEXT_MISMATCH", "RESOLUTION_WINDOW_INVALID",
    "RESOLUTION_ASSIGNMENT_BUNDLE_MISMATCH", "UNSUPPORTED_RESOLUTION_OR_FALLBACK", "LAUNCH_INTEGRITY_INVALID",
    "LAUNCH_CONTEXT_MISMATCH", "LAUNCH_WINDOW_INVALID", "LAUNCH_ASSIGNMENT_LINK_MISMATCH",
    "NAMESPACE_UNKNOWN", "NAMESPACE_REQUIRED", "NAMESPACE_CONDITION_CONFLICT", "SOURCE_CONTEXT_WINDOW_INACTIVE",
    "PROFILE_FREEZE_AFTER_OBSERVATION", "CONTROLLER_NO_LONGER_ELIGIBLE_FOR_PUBLICATION",
    "CONTROLLER_TASK_CONTEXT_MISMATCH",
    "CONFIGURATION_AFTER_OBSERVATION",
    "CONTENT_DECLARATIONS_PENDING", "PROMPT_NOT_REGISTERED", "GENERATION_NOT_REGISTERED",
    "PROMPT_NONCANONICAL", "PROMPT_FORMAT", "PROMPT_CATALOG_TASK_SOURCE_MISMATCH",
    "PROMPT_RESOLUTION_MISMATCH", "GENERATION_UNSUPPORTED_JOINT_TUPLE", "GENERATION_FIELD_TYPE",
})

_PRIVATE = "_wss_wp05_pinned_cpc2"


def _dependency(name: str):
    # Do not import a sys.path-selected cpc2 and only inspect it afterward:
    # its code could already have executed. The verified bundle is loaded into
    # its own package namespace with an exact local __path__ for relative refs.
    root = Path(__file__).resolve().parents[2] / "references"
    expected = root / "cpc_release/implementation/src/cpc2"
    if name not in {"profile", "schema", "integrity"}:
        raise ProducerError("UNPINNED_CPC_DEPENDENCY")
    for key, module in tuple(sys.modules.items()):
        if key == _PRIVATE or key.startswith(_PRIVATE + "."):
            filename = getattr(module, "__file__", None)
            if filename is None or not Path(filename).resolve().is_relative_to(expected):
                raise ProducerError("UNPINNED_CPC_DEPENDENCY")
    def load(fullname, file, package=False):
        if fullname not in sys.modules:
            verify_pinned_references(root)  # before executing any bundled module
            spec = importlib.util.spec_from_file_location(fullname, file,
                submodule_search_locations=[str(expected)] if package else None)
            module = importlib.util.module_from_spec(spec)
            sys.modules[fullname] = module
            try:
                # Direct compile/exec of verified local source avoids implicit
                # .pyc writes into the frozen source/reference tree. Relative
                # dependencies are preloaded below into this same namespace.
                exec(compile(file.read_bytes(), str(file), "exec", dont_inherit=True), module.__dict__)
            except Exception:
                del sys.modules[fullname]
                raise
        return sys.modules[fullname]
    load(_PRIVATE, expected / "__init__.py", True)
    load(_PRIVATE + ".common", expected / "common.py")
    load(_PRIVATE + ".schema", expected / "schema.py")
    return load(_PRIVATE + "." + name, expected / (name + ".py"))


def _shape(value: dict, name: str, policy: ProducerPolicy) -> None:
    if _dependency("schema").validate_named(value, name,
            max_identifier_chars=policy.profile["input_limits"]["max_identifier_chars"]):
        raise ProducerError("SIGNED_OBJECT_SCHEMA_INVALID")


@dataclass(frozen=True, slots=True)
class ProducerPolicy:
    """New external profile/map/key declarations for synthetic offline use only.

    Constructor verifies the pinned profile schema/policy and five logical key
    roles. Nothing here attests owner authority, actual review, native facts or
    deployment readiness. Keys are never serialized by the producer.
    """
    profile_raw: bytes = field(repr=False)
    bundle_map_raw: bytes = field(repr=False)
    key_registry: Mapping[str, bytes] = field(repr=False)
    valid_from: str
    expires_at: str
    configuration_time: str
    controller_context_digest: str
    task_id: str
    task_version: str
    profile: Mapping = field(init=False, repr=False)
    bundle_map: Mapping = field(init=False, repr=False)

    def __post_init__(self) -> None:
        require_digest(self.controller_context_digest, "controller_context_digest")
        require_identifier(self.task_id, "policy.task_id")
        require_identifier(self.task_version, "policy.task_version")
        if not instant(self.valid_from) <= instant(self.configuration_time) < instant(self.expires_at):
            raise ProducerError("POLICY_WINDOW_INVALID")
        for raw in (self.profile_raw, self.bundle_map_raw):
            if type(raw) is not bytes or not 0 < len(raw) <= 1048576:
                raise ProducerError("POLICY_IMMUTABLE_BYTES_REQUIRED")
        profile = decode_json_object(self.profile_raw)
        mapping = decode_json_object(self.bundle_map_raw)
        if canonical_json_bytes(profile) != self.profile_raw or canonical_json_bytes(mapping) != self.bundle_map_raw:
            raise ProducerError("POLICY_NONCANONICAL")
        root = Path(__file__).resolve().parents[2] / "references"
        verify_pinned_references(root)  # explicit load call, not an import side effect
        keys = dict(self.key_registry)
        if _dependency("profile").validate_profile(profile, self.configuration_time, keys):
            raise ProducerError("PROFILE_OR_ROLE_KEY_POLICY_INVALID")
        maximum = profile["input_limits"]["max_identifier_chars"]
        # Longest signed new ref is actual-generation:<32hex>; controller
        # invocation/attempt use standard UUIDs (47/44 chars respectively).
        if maximum < 50 or max(len(self.task_id), len(self.task_version)) > maximum:
            raise ProducerError("PRODUCER_IDENTIFIER_CAPACITY_UNSUPPORTED")
        if set(keys) != set(profile["issuer_key_policy"].values()):
            raise ProducerError("UNSCOPED_KEY_REGISTRY")
        # The pinned profile only supports SYNTHETIC_ONLY ASCII material.
        keys = {name: value.encode("ascii") if isinstance(value, str) else value for name, value in keys.items()}
        if set(profile["conditions"]) != {"hint", "answer"} or profile["resource_condition_map"] != {
                resource: condition for condition, resource in RESOURCES.items()}:
            raise ProducerError("UNSUPPORTED_WSS_CONDITION_POLICY")
        require_mapping(mapping, "bundle_map", required=tuple(RESOURCES.values()))
        bundles = []
        for resource, configs in mapping.items():
            require_mapping(configs, "bundle_configs", required=JOINT_CONFIGS)
            for bundle in configs.values():
                require_identifier(bundle, "bundle")
                bundles.append(bundle)
        if len(set(bundles)) != 10 or set(bundles) != set(profile["artifact_registry"]):
            raise ProducerError("BUNDLE_MAP_NOT_TOTAL_TEN_UNIQUE")
        object.__setattr__(self, "profile", freeze_json(profile))
        object.__setattr__(self, "bundle_map", freeze_json(mapping))
        object.__setattr__(self, "key_registry", MappingProxyType(keys))

    def active(self, utc: str) -> None:
        if not instant(self.valid_from) <= instant(utc) < instant(self.expires_at):
            raise ProducerError("POLICY_WINDOW_INACTIVE")
        if instant(self.configuration_time) > instant(utc):
            raise ProducerError("CONFIGURATION_AFTER_OBSERVATION")


def _common(policy: ProducerPolicy, resolution: dict) -> dict:
    p = policy.profile
    return {"contract_version": "2.0.1", "profile_id": p["profile_id"],
            "profile_version": p["profile_version"], "experiment_id": p["experiment_id"],
            "experiment_version": p["experiment_version"], "unit_token": resolution["unit_token"],
            "audience": p["expected_audience"], "deployment_id": p["deployment_id"],
            "context_id": p["context_id"], "valid_from": policy.valid_from, "expires_at": policy.expires_at}


def _sign(policy: ProducerPolicy, value: dict, issuer: str, *, proof: bool) -> dict:
    signed = plain_json(value)
    digest = sha(canonical_json_bytes(signed))
    key_id = policy.profile["issuer_key_policy"][issuer]
    integrity = {"algorithm": "HMAC-SHA256", "key_id": key_id, "content_digest": digest,
                 "mac": "hmac-sha256:" + hmac.new(policy.key_registry[key_id], digest.encode("ascii"),
                                                   hashlib.sha256).hexdigest()}
    return {"body": signed, "integrity": integrity} if proof else {**signed, "integrity": integrity}


def _proof(policy: ProducerPolicy, resolution: dict, kind: str, observed: ClockObservation, **extra) -> dict:
    issuer = policy.profile["proof_issuers"][kind]
    body = {**_common(policy, resolution), "proof_id": new_ref("proof"), "issuer": issuer,
            "issued_at": observed.utc, "clock_id": observed.clock_id, "sequence": observed.sequence, **extra}
    result = _sign(policy, body, issuer, proof=True)
    _shape(result, kind, policy)
    return result


def _resolution(policy: ProducerPolicy, raw: bytes, binding: ResolutionBinding,
                attempt_ref: str, logical_resource: str, config_id: str, now: str) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= 1048576:
        raise ProducerError("RESOLUTION_RAW_BYTES_REQUIRED")
    value = decode_json_object(raw)
    _shape(value, "resolution", policy)
    profile, keys = plain_json(policy.profile), dict(policy.key_registry)
    if not _dependency("integrity").verify_record(value, profile, keys)[0]:
        raise ProducerError("RESOLUTION_INTEGRITY_INVALID")
    expected = {**_common(policy, value), "schema_version": "cpc-2.0.1", "unit_token": attempt_ref}
    for name in ("contract_version", "profile_id", "profile_version", "schema_version", "experiment_id",
                 "experiment_version", "unit_token", "audience", "deployment_id", "context_id"):
        if value[name] != expected[name]:
            raise ProducerError("RESOLUTION_CONTEXT_MISMATCH")
    if not instant(value["valid_from"]) <= instant(value["issued_at"]) <= instant(now) < instant(value["expires_at"]):
        raise ProducerError("RESOLUTION_WINDOW_INVALID")
    if (value["record_id"] != binding.resolution_ref or binding.context_ref != profile["context_id"]
            or logical_resource != binding.logical_resource_id or config_id != binding.config_id
            or policy.bundle_map[logical_resource][config_id] != binding.bundle_ref):
        raise ProducerError("RESOLUTION_ASSIGNMENT_BUNDLE_MISMATCH")
    payload = value["payload"]
    if (payload["requested_condition"] != binding.condition or payload["resolved_condition"] != binding.condition
            or payload["resolver_version"] != profile["resolver_version"] or payload["fallback_used"]
            or payload["fallback_authorized"] or payload["authorization_ref"] is not None):
        raise ProducerError("UNSUPPORTED_RESOLUTION_OR_FALLBACK")
    launch = payload["launch_attestation"]
    if not _dependency("integrity").verify_proof(launch, "launch_attestation", profile, keys)[0]:
        raise ProducerError("LAUNCH_INTEGRITY_INVALID")
    body = launch["body"]
    for name in ("contract_version", "profile_id", "profile_version", "experiment_id", "experiment_version",
                 "unit_token", "audience", "deployment_id", "context_id"):
        if body[name] != value[name]:
            raise ProducerError("LAUNCH_CONTEXT_MISMATCH")
    if not (instant(body["valid_from"]) <= instant(body["issued_at"]) <= instant(value["issued_at"])
            and instant(now) < instant(body["expires_at"])):
        raise ProducerError("LAUNCH_WINDOW_INVALID")
    if (body["assignment_record_id"] != value["predecessor_record_id"]
            or body["assignment_digest"] != value["predecessor_digest"]
            or body["resource_id"] != logical_resource or body["launch_nonce"] != payload["launch_nonce"]
            or body["namespace_values"] != payload["claim_namespaces"]):
        raise ProducerError("LAUNCH_ASSIGNMENT_LINK_MISMATCH")
    namespace_values = payload["claim_namespaces"]
    if set(namespace_values) - set(profile["namespace_policy"]):
        raise ProducerError("NAMESPACE_UNKNOWN")
    for name, rule in profile["namespace_policy"].items():
        if rule["required"] and name not in namespace_values:
            raise ProducerError("NAMESPACE_REQUIRED")
        if name in namespace_values and rule["role"] != "descriptive" and rule["mapping"].get(namespace_values[name]) != binding.condition:
            raise ProducerError("NAMESPACE_CONDITION_CONFLICT")
    return value


def _active(policy: ProducerPolicy, resolution: dict, observed: ClockObservation) -> None:
    policy.active(observed.utc)
    if observed.clock_id != policy.profile["observer_clock_id"]:
        raise ProducerError("OBSERVER_CLOCK_CONTEXT_MISMATCH")
    if instant(policy.profile["freeze_timestamp"]) > instant(observed.utc):
        raise ProducerError("PROFILE_FREEZE_AFTER_OBSERVATION")
    for value in (resolution, resolution["payload"]["launch_attestation"]["body"]):
        if not instant(value["valid_from"]) <= instant(observed.utc) < instant(value["expires_at"]):
            raise ProducerError("SOURCE_CONTEXT_WINDOW_INACTIVE")


@dataclass(frozen=True, slots=True)
class ProductionResult:
    call_ref: str
    invocation_ref: str | None
    status: str
    publication: str
    controller_reconciled: bool
    exposure_reference: SnapshotReference | None
    failure_reference: SnapshotReference | None
    error_code: str | None
    root: str | None


def produce(controller: OfflineController, attempt_ref: str, *, logical_resource: str, config_id: str,
            root: str | Path, policy: ProducerPolicy, resolution_raw: bytes,
            prompt_raw: bytes, generation_raw: bytes, catalog: CatalogSnapshot,
            binding: ResolutionBinding, clock: LocalClock | None = None,
            preallocated_invocation_ref: str | None = None) -> ProductionResult:
    """Explicit offline local call; allocates invocation before preprocessing.

    A caller that records receipt before obtaining external help inputs may
    supply that exact still-unconsumed RECEIVED invocation. This path never
    allocates a replacement or mutates an ineligible supplied invocation.

    A new directory is required for every call. No retry, overwrite, recovery or
    native/provider interaction. Failures keep files and return INCOMPLETE with
    explicit known/unknown publication. Controller IO failure requires external
    reconciliation from these sidecars; it can never be interpreted as no call.
    """
    if type(controller) is not OfflineController:
        raise ProducerError("CONTROLLER_REQUIRED")
    call_ref = new_ref("producer-call")  # caller-visible even if allocation is uncertain
    before, invocation, allocation_attempted = None, None, False
    if preallocated_invocation_ref is not None:
        try:
            state = controller.view()
        except Exception:
            return ProductionResult(call_ref, None, "ALLOCATION_UNRESOLVED", "NONE", False,
                                    None, None, "CONTROLLER_ALLOCATION_UNRESOLVED", None)
        # Only an identity actually present in this controller can be adopted.
        # A known but mismatched identity remains visible in the refusal result,
        # while its ledger row and publication accounting remain untouched.
        row = (state["invocations"].get(preallocated_invocation_ref)
               if type(preallocated_invocation_ref) is str else None)
        invocation = preallocated_invocation_ref if row is not None else None
        attempt = state["attempts"].get(attempt_ref) if type(attempt_ref) is str else None
        eligible = (row is not None and attempt is not None
            and row["attempt_ref"] == attempt_ref and row["logical_resource"] == logical_resource
            and row["config_id"] == config_id and row["stage"] == "RECEIVED"
            and row["history"] == ("RECEIVED",) and not row["settled"]
            and not row["ever_published"] and not row["publication_unresolved"]
            and not any(p["invocation_ref"] == invocation for p in state["publications"].values())
            and state["active_attempt"] == attempt_ref and attempt["closed_sequence"] is None
            and attempt["logical_resource"] == logical_resource and attempt["config_id"] == config_id
            and state["pending_operation"] is None and not state["stopped_flags"]
            and not controller.context.readiness_issues())
        if not eligible:
            return ProductionResult(call_ref, invocation, "PRECONDITION_REFUSED", "NONE", True,
                                    None, None, "CONTROLLER_PRECONDITION_REFUSED", None)
    try:
        if preallocated_invocation_ref is None:
            before = controller.view()
            allocation_attempted = True
            invocation = controller.receive_help(attempt_ref, logical_resource=logical_resource, config_id=config_id)
            state = controller.view()
    except Exception:
        # Read-only reconciliation may recover a unique explicit local ledger
        # identity, never a guessed timestamp/native ID. Ambiguity stays None.
        if invocation is None and before is not None:
            try:
                after = controller.view()
                new_ids = set(after["invocations"]) - set(before["invocations"])
                if len(new_ids) == 1:
                    candidate = next(iter(new_ids))
                    row = after["invocations"][candidate]
                    if (row["attempt_ref"] == attempt_ref and row["logical_resource"] == logical_resource
                            and row["config_id"] == config_id):
                        invocation = candidate
            except Exception:
                pass
        return ProductionResult(call_ref, invocation,
            "ALLOCATION_UNRESOLVED" if allocation_attempted else "ALLOCATION_NOT_STARTED",
            "NONE", False, None, None, "CONTROLLER_ALLOCATION_UNRESOLVED", None)
    if state["invocations"][invocation]["settled"]:
        return ProductionResult(call_ref, invocation, "PRECONDITION_REFUSED", "NONE", True, None, None,
                                "CONTROLLER_PRECONDITION_REFUSED", None)
    store, target, exposure_ref, failure_ref = None, None, None, None
    publication, stage = "NONE", "RECEIVED"
    controller_io_uncertain = False
    def change(call, *args, **kwargs):
        nonlocal controller_io_uncertain
        try:
            return call(*args, **kwargs)
        except Exception:
            controller_io_uncertain = True
            raise
    try:
        if type(policy) is not ProducerPolicy or type(binding) is not ResolutionBinding or type(catalog) is not CatalogSnapshot:
            raise ProducerError("TYPED_PRODUCER_INPUT_REQUIRED")
        if (sha(canonical_json_bytes(controller.context.to_mapping())) != policy.controller_context_digest
                or binding.task_id != policy.task_id or binding.task_version != policy.task_version):
            raise ProducerError("CONTROLLER_TASK_CONTEXT_MISMATCH")
        clock = LocalClock(policy.profile["observer_clock_id"]) if clock is None else clock
        if type(clock) is not LocalClock or clock.clock_id != policy.profile["observer_clock_id"]:
            raise ProducerError("OBSERVER_CLOCK_CONTEXT_MISMATCH")
        initial = clock.observe()
        policy.active(initial.utc)
        target = _real_directory(root, exists=False)
        target.mkdir(mode=0o700, exist_ok=False)
        _fsync_directory(target.parent)
        store = IndexedSnapshotStore.create(target / "snapshots", new_ref("producer-store"))
        ProducerReferenceIndex.create(target / "reference-index",store,call_ref=call_ref,invocation_ref=invocation)
        # Keys never enter files. Raw supplied resolution retained before parsing.
        save(store, "operator-profile", policy.profile_raw)
        save(store, "operator-bundle-map", policy.bundle_map_raw)
        save(store, "received-resolution", resolution_raw)
        save(store, "producer-context", canonical_json_bytes({
            "format": "wss-producer-context-v1", "invocation_ref": invocation, "attempt_ref": attempt_ref,
            "call_ref": call_ref,
            "controller_scope": controller.scope.to_mapping(),
            "key_ids_only": list(policy.key_registry), "profile_digest": sha(policy.profile_raw),
            "bundle_map_digest": sha(policy.bundle_map_raw), "clock": initial.to_mapping(),
            "valid_from": policy.valid_from, "expires_at": policy.expires_at,
            "configuration_time": policy.configuration_time,
            "controller_context_digest": policy.controller_context_digest,
            "task_id": policy.task_id, "task_version": policy.task_version,
            "evidence_class": "SYNTHETIC_OFFLINE_MECHANICAL_QA", "keys_or_authority_verified_external": False,
        }))
        resolution = _resolution(policy, resolution_raw, binding, attempt_ref, logical_resource, config_id, initial.utc)
        _active(policy, resolution, initial)
        change(controller.advance_invocation, invocation, "CONSUME_STARTED", evidence_ref="local:wp05-consume-start")
        stage = "CONSUME_STARTED"
        consumed = capture_and_render(prompt_raw, generation_raw, catalog, binding, store, invocation, clock)
        use = consumed.observation
        _active(policy, resolution, use)
        if instant(use.utc) < instant(resolution["issued_at"]):
            raise ProducerError("USE_BEFORE_RESOLUTION")
        registered = policy.profile["artifact_registry"][binding.bundle_ref]
        artifacts = plain_json(registered)
        measured = {}
        for name, capture, use_ref in (("prompt", consumed.prompt_reference, consumed.prompt_use_reference),
                                       ("generation", consumed.generation_reference, consumed.generation_use_reference)):
            actual = capture.sha256
            if actual != registered[name]["digest"]:
                raise ProducerError("ACTUAL_CAPTURE_REGISTRY_MISMATCH")
            artifacts[name] = {"version": registered[name]["version"], "digest": actual, "evidence_mode": "measured"}
            measured[name] = {"component_id": name, "version": registered[name]["version"], "digest": actual,
                              "capture_ref": capture.snapshot_ref, "use_ref": use_ref.snapshot_ref}
        links = {"invocation_id": invocation, "resolution_record_id": resolution["record_id"],
                 "resolution_digest": resolution["integrity"]["content_digest"]}
        usage = _proof(policy, resolution, "usage_attestation", use, **links, measured_components=measured)
        save(store, "usage-proof", canonical_json_bytes(usage))
        staged = save(store, "staged-response-not-release", consumed.result.body)
        change(controller.advance_invocation, invocation, "CAPTURED", evidence_ref=consumed.manifest_reference.snapshot_ref)
        stage = "CAPTURED"
        committed = clock.observe()
        _active(policy, resolution, committed)
        commitment = _proof(policy, resolution, "commitment", committed, **links,
            enacted_condition=binding.condition, artifact_version=binding.bundle_ref,
            artifacts=artifacts, usage_attestation=usage)
        commitment_raw = canonical_json_bytes(commitment)
        commitment_ref = save(store, "signed-commitment", commitment_raw)
        durable = clock.observe()  # only after file+directory fsync and readback
        _active(policy, resolution, durable)
        durable_ref = save(store, "commitment-durable-receipt", canonical_json_bytes({
            "commitment_reference": commitment_ref.to_mapping(), "full_commitment_digest": sha(commitment_raw),
            "created_signed": committed.to_mapping(), "durable_complete_observed": durable.to_mapping(),
            "file_fsync_directory_fsync_readback_completed": True,
        }))
        change(controller.advance_invocation, invocation, "COMMIT_DURABLE", evidence_ref=durable_ref.snapshot_ref)
        stage = "COMMIT_DURABLE"
        if store.get(staged) != consumed.result.body or store.get(commitment_ref) != commitment_raw:
            raise ProducerError("PREPUBLICATION_PERSISTED_BYTES_MISMATCH")
        current = controller.view()
        if (current["active_attempt"] != attempt_ref or current["attempts"][attempt_ref]["closed_sequence"] is not None
                or current["stopped_flags"] or current["invocations"][invocation]["settled"]):
            raise ProducerError("CONTROLLER_NO_LONGER_ELIGIBLE_FOR_PUBLICATION")
        release_dir = target / "publications"
        release_dir.mkdir(mode=0o700, exist_ok=False)
        _fsync_directory(target)
        exposure_id = new_ref("exposure")
        publication = "UNRESOLVED"  # set BEFORE any possible visible response bytes
        _new_file(release_dir / "response.txt", consumed.result.body)
        _fsync_directory(release_dir)
        publication = "PUBLISHED"  # boundary completed; later errors cannot erase it
        change(controller.advance_invocation, invocation, "PUBLISHED", evidence_ref="local:durable-response-file")
        stage = "PUBLISHED"
        released = clock.observe()  # real observation after boundary, never signed beforehand
        _active(policy, resolution, released)
        if not (instant(use.utc) <= instant(committed.utc) < instant(released.utc)
                and use.sequence <= committed.sequence < released.sequence
                and durable.monotonic_ns <= released.monotonic_ns):
            raise ProducerError("RELEASE_ORDER_NOT_ESTABLISHED")
        if _read_file(release_dir / "response.txt", 1048576) != consumed.result.body:
            raise ProducerError("PUBLISHED_RESPONSE_READBACK_MISMATCH")
        publication_ref = save(store, "publication-receipt", canonical_json_bytes({
            "invocation_ref": invocation, "exposure_record_id": exposure_id,
            "release_boundary": "durable_local_response_file", "relative_file": "publications/response.txt",
            "body_digest": sha(consumed.result.body), "full_commitment_digest": sha(commitment_raw),
            "observed_release": released.to_mapping(), "file_directory_fsync_completed": True,
        }))
        release = _proof(policy, resolution, "release_attestation", released,
            invocation_id=invocation, commitment_digest=sha(commitment_raw), exposure_record_id=exposure_id,
            release_boundary="durable_local_response_file")
        save(store, "release-proof", canonical_json_bytes(release))
        exposed = clock.observe()
        _active(policy, resolution, exposed)
        if instant(exposed.utc) < instant(released.utc):
            raise ProducerError("EXPOSURE_BEFORE_RELEASE")
        record = {**_common(policy, resolution), "record_id": exposure_id, "record_type": "exposure",
            "schema_version": "cpc-2.0.1", "issuer": policy.profile["record_issuers"]["exposure"],
            "nonce": new_ref("nonce"), "issued_at": exposed.utc,
            "predecessor_record_id": resolution["record_id"], "predecessor_digest": resolution["integrity"]["content_digest"],
            "payload": {"enacted_condition": binding.condition, "artifact_version": binding.bundle_ref,
                "artifacts": artifacts, "invocation_id": invocation, "commitment": commitment,
                "release_attestation": release}}
        exposure = _sign(policy, record, record["issuer"], proof=False)
        _shape(exposure, "exposure", policy)
        exposure_ref = save(store, "final-exposure", canonical_json_bytes(exposure))
        save(store, "complete-manifest", canonical_json_bytes({
            "format": "wss-production-v1", "invocation_ref": invocation, "publication": publication,
            "consumption_reference": consumed.manifest_reference.to_mapping(),
            "staged_body_reference": staged.to_mapping(), "commitment_reference": commitment_ref.to_mapping(),
            "durability_reference": durable_ref.to_mapping(), "publication_reference": publication_ref.to_mapping(),
            "exposure_reference": exposure_ref.to_mapping(), "exposure_observed": exposed.to_mapping(),
            "core_admission_performed": False, "independent_secure_observer": False,
        }))
        change(controller.finish_invocation, invocation, publication="PUBLISHED", evidence_ref=exposure_ref.snapshot_ref)
        return ProductionResult(call_ref, invocation, "COMPLETE", "PUBLISHED", True, exposure_ref, None, None, str(target))
    except Exception as error:
        # Never store exception text/args/tracebacks that could expose key/input
        # material. A closed failure code and retained bytes suffice for audit.
        if type(error) in (ProducerError, RendererError) and str(error) in _SAFE_CODES:
            code = str(error)
        elif type(error) in (ProducerError, RendererError, ContractError, OSError, FileExistsError,
                             ValueError, TypeError, RuntimeError, StopIteration, UnicodeError):
            code = "WP05_" + type(error).__name__
        else:
            code = "WP05_UNEXPECTED_EXCEPTION"
        if store is not None:
            try:
                failure_ref = save(store, "failure-receipt", canonical_json_bytes({
                    "format": "wss-producer-failure-v1", "invocation_ref": invocation,
                    "call_ref": call_ref,
                    "stage": stage, "publication": publication, "error_code": code,
                    "final_exposure_reference": None if exposure_ref is None else exposure_ref.to_mapping(),
                    "clock_observations_including_failed_order": [o.to_mapping() for o in clock.observations]
                        if type(clock) is LocalClock else [],
                    "retry_or_cleanup_performed": False, "requires_reconciliation": True,
                }))
            except Exception:
                pass  # retain orphan files and return explicit unresolved state
        reconciled = False
        try:
            if controller_io_uncertain:
                raise ProducerError("CONTROLLER_RECONCILIATION_REQUIRED")
            controller.finish_invocation(invocation, publication=publication,
                evidence_ref=failure_ref.snapshot_ref if failure_ref is not None else "local:wp05-incomplete:" + code)
            reconciled = True
        except Exception:
            pass  # a poisoned/partial controller journal must not be repaired
        return ProductionResult(call_ref, invocation, "INCOMPLETE", publication, reconciled, exposure_ref,
                                failure_ref, code, None if target is None else str(target))
