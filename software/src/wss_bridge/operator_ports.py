"""Explicit supplied local declarations for the worked runner, never authority.

No profile, key, rights, consent or source fact is manufactured here. Signed
metadata is produced only from caller-supplied frozen policy/materials/context.
The inherited HMAC policy is SYNTHETIC_ONLY, not a production trust service.
"""
from __future__ import annotations

import hashlib
import hmac
from types import MappingProxyType
from typing import Mapping, Callable
import uuid

from .capture import LocalClock, instant
from .cpc_adapter import AdmissionContext
from .controller import ControllerContext
from .outcomes import OutcomeRecipe
from .primitives import (ContractError, canonical_json_bytes, decode_json_object,
                         plain_json, require_identifier, require_mapping,
                         require_bool, require_rfc3339)
from .producer import ProducerPolicy, _shape
from .renderer import (CatalogSnapshot, Generation, ResolutionBinding, RESOURCES,
                       JOINT_CONFIGS, PROMPT_FIELDS, TASK_FIELDS)
from .worked_runner import (HelpInputs, HelpRequest, OutcomeRequest, RunnerPorts)


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _ref(kind: str) -> str:
    return "operator:" + kind + ":" + uuid.uuid4().hex


class SuppliedOperatorPorts:
    """Current operator-supplied metadata ports with exact immutable materials.

    No native/network/process access is performed. Schema checks reuse only the
    inherited pinned reference loader; no user-named plugin is loaded. Policy
    signatures assert supplied declarations only; opaque human references are
    not checked against an external approval service. Caller owns that evidence.
    """

    def __init__(self, policy: ProducerPolicy, context: ControllerContext,
                 catalog: CatalogSnapshot, prompts_by_condition: Mapping,
                 generations_by_config: Mapping, recipe: OutcomeRecipe,
                 content_review_ref: str, internal_rights_ref: str,
                 consent_declaration: Mapping, eligibility_declaration: bool,
                 operation: Callable, *, clock: LocalClock | None = None):
        if (type(policy) is not ProducerPolicy or type(context) is not ControllerContext
                or type(catalog) is not CatalogSnapshot or type(recipe) is not OutcomeRecipe
                or not callable(operation)):
            raise ContractError("operator ports require typed supplied dependencies")
        self._policy, self._context, self._catalog, self._recipe = policy, context, catalog, recipe
        self._review = require_identifier(content_review_ref, "content_review_ref")
        self._rights = require_identifier(internal_rights_ref, "internal_rights_ref")
        require_bool(eligibility_declaration, "eligibility_declaration")
        self._eligibility = eligibility_declaration
        self._clock = LocalClock(policy.profile["observer_clock_id"]) if clock is None else clock
        if (type(self._clock) is not LocalClock or self._clock.source != "REAL_UTC"
                or self._clock.clock_id != policy.profile["observer_clock_id"]):
            raise ContractError("operator ports require current real UTC policy clock")
        if context.readiness_issues():
            raise ContractError("operator context unresolved")
        if _sha(canonical_json_bytes(context.to_mapping())) != policy.controller_context_digest:
            raise ContractError("operator policy context binding differs")
        if (catalog.task["task_id"] != policy.task_id
                or catalog.task["task_version"] != policy.task_version
                or context.task_version_ref != policy.task_version):
            raise ContractError("operator task version differs")
        consent = require_mapping(consent_declaration, "consent_declaration",
            required=("state", "at", "authority_ref", "policy_version"))
        require_identifier(consent["state"], "consent.state")
        require_rfc3339(consent["at"], "consent.at")
        require_identifier(consent["authority_ref"], "consent.authority_ref")
        if (consent["authority_ref"] not in policy.profile["consent_authority_refs"]
                or consent["policy_version"] != policy.profile["consent_policy_version"]):
            raise ContractError("consent policy/authority differs")
        self._consent = MappingProxyType(dict(consent))
        if set(prompts_by_condition) != set(RESOURCES):
            raise ContractError("exact two condition prompts required")
        if set(generations_by_config) != set(JOINT_CONFIGS):
            raise ContractError("exact five supplied generation configs required")
        prompts, generations = {}, {}
        for condition, raw in prompts_by_condition.items():
            if type(raw) is not bytes or not 0 < len(raw) <= 1048576:
                raise ContractError("immutable bounded prompt bytes required")
            value = require_mapping(decode_json_object(raw), "operator.prompt", required=PROMPT_FIELDS)
            if (canonical_json_bytes(value) != raw or value["prompt_format"] != "wss-prompt-v2"
                    or value["catalog_version"] != catalog.catalog_version
                    or value["logical_resource_id"] != RESOURCES[condition]
                    or any(value[k] != catalog.task[k] for k in TASK_FIELDS)):
                raise ContractError("operator prompt/catalog/task mismatch")
            prompts[condition] = raw
        for config, raw in generations_by_config.items():
            if type(raw) is not bytes:
                raise ContractError("immutable generation bytes required")
            g = Generation.from_bytes(raw)
            if g.config_id != config or g.canonical_bytes != raw:
                raise ContractError("operator generation/config mismatch")
            generations[config] = raw
        self._prompts = MappingProxyType(prompts)
        self._generations = MappingProxyType(generations)
        for condition, resource in RESOURCES.items():
            for config in JOINT_CONFIGS:
                vector = policy.profile["artifact_registry"][policy.bundle_map[resource][config]]
                if (vector["prompt"]["digest"] != _sha(prompts[condition])
                        or vector["generation"]["digest"] != _sha(generations[config])):
                    raise ContractError("operator input registry mismatch")
        rd = recipe.data
        if (rd["task_version_ref"] != context.task_version_ref
                or rd["followup_item_digest"] != context.followup_target.item_digest
                or rd["followup_presentation_digest"] != context.followup_target.item_presentation_digest
                or rd["review_ref"] != self._review or rd["rights_ref"] != self._rights):
            raise ContractError("operator recipe/source/review/rights binding differs")
        self._issued: dict[str, dict] = {}
        self._used_invocations: set[str] = set()
        self._attempt_assignments: dict[str, tuple] = {}
        self._publication_ordinals: dict[str, int] = {}
        self._signed_outcomes: set[str] = set()
        self._now()
        self.ports = RunnerPorts(operation, self.help_inputs, self.sign_outcome,
                                 self.admission_context, recipe)

    def __repr__(self):
        return "SuppliedOperatorPorts(supplied_declarations_only=True, key_material=<redacted>)"

    def _now(self) -> str:
        now = self._clock.observe().utc
        self._policy.active(now)
        if instant(self._policy.profile["freeze_timestamp"]) > instant(now):
            raise ContractError("operator profile freeze is in the future")
        if instant(self._consent["at"]) > instant(now):
            raise ContractError("operator consent declaration is in the future")
        return now

    def _common(self, attempt: str) -> dict:
        require_identifier(attempt, "attempt_ref")
        p = self._policy.profile
        return {**{k: p[k] for k in ("contract_version", "profile_id", "profile_version",
            "schema_version", "experiment_id", "experiment_version", "deployment_id", "context_id")},
            "unit_token": attempt, "audience": p["expected_audience"],
            "valid_from": self._policy.valid_from, "expires_at": self._policy.expires_at}

    def _sign(self, value: dict, issuer: str, *, proof=False) -> dict:
        content = plain_json(value)
        digest = _sha(canonical_json_bytes(content))
        key_id = self._policy.profile["issuer_key_policy"][issuer]
        integrity = {"algorithm": "HMAC-SHA256", "key_id": key_id,
            "content_digest": digest, "mac": "hmac-sha256:" + hmac.new(
                self._policy.key_registry[key_id], digest.encode("ascii"), hashlib.sha256).hexdigest()}
        return {"body": content, "integrity": integrity} if proof else {**content, "integrity": integrity}

    def _verified_record(self, raw: bytes, kind: str) -> dict:
        if type(raw) is not bytes or not 0 < len(raw) <= 1048576:
            raise ContractError("immutable bounded signed record required")
        record = decode_json_object(raw)
        if canonical_json_bytes(record) != raw:
            raise ContractError("noncanonical supplied record")
        _shape(record, kind, self._policy)
        integrity = record.get("integrity")
        if type(integrity) is not dict or record.get("record_type") != kind:
            raise ContractError("signed record shape differs")
        issuer = self._policy.profile["record_issuers"][kind]
        if record.get("issuer") != issuer:
            raise ContractError("signed record issuer differs")
        body = {k: v for k, v in record.items() if k != "integrity"}
        expected = self._sign(body, issuer)["integrity"]
        if set(integrity) != set(expected) or any(
                type(integrity[k]) is not str or not hmac.compare_digest(integrity[k], expected[k])
                for k in expected):
            raise ContractError("supplied record integrity differs")
        return record

    def help_inputs(self, request: HelpRequest) -> HelpInputs:
        if type(request) is not HelpRequest or request.context.to_mapping() != self._context.to_mapping():
            raise ContractError("operator help context differs")
        require_identifier(request.invocation_ref, "invocation_ref")
        if request.invocation_ref in self._used_invocations:
            raise ContractError("operator help invocation already issued")
        if len(self._used_invocations) >= 96:
            raise ContractError("operator help publication capacity exhausted")
        resource, config = request.episode.logical_resource, request.episode.config_id
        condition = next((c for c, r in RESOURCES.items() if r == resource), None)
        if condition is None or config not in self._generations:
            raise ContractError("operator help assignment/config unsupported")
        assignment_tuple = (resource, config, request.episode.episode_ref, request.episode.publications)
        if (request.attempt_ref in self._attempt_assignments
                and self._attempt_assignments[request.attempt_ref] != assignment_tuple):
            raise ContractError("operator attempt assignment changed")
        if (type(request.publication_ordinal) is not int
                or not 1 <= request.publication_ordinal <= request.episode.publications
                or request.publication_ordinal != self._publication_ordinals.get(request.attempt_ref, 0) + 1):
            raise ContractError("operator publication ordinal differs")
        now = self._now()
        common, p = self._common(request.attempt_ref), self._policy.profile
        assignment_id, resolution_id, launch_nonce = _ref("assignment"), _ref("resolution"), _ref("launch-nonce")
        namespace_values = {}
        for name, rule in p["namespace_policy"].items():
            if rule["role"] in ("authoritative", "consistency"):
                options = [raw for raw, c in rule["mapping"].items() if c == condition]
                if rule["required"] and not options:
                    raise ContractError("operator namespace lacks assigned condition")
                if options:
                    namespace_values[name] = sorted(options)[0]
        assignment = self._sign({**common, "record_id": assignment_id, "record_type": "assignment",
            "issuer": p["record_issuers"]["assignment"], "nonce": _ref("nonce"), "issued_at": now,
            "predecessor_record_id": None, "predecessor_digest": None,
            "payload": {"assigned_condition": condition, "assignment_policy_version": p["assignment_policy_version"],
                "scope": p["scope"], "resource_id": resource, "launch_nonce": launch_nonce}}, p["record_issuers"]["assignment"])
        launch_common = {k: v for k, v in common.items() if k != "schema_version"}
        launch = self._sign({**launch_common, "proof_id": _ref("launch"), "issuer": p["proof_issuers"]["launch_attestation"],
            "issued_at": now, "assignment_record_id": assignment_id,
            "assignment_digest": assignment["integrity"]["content_digest"], "resource_id": resource,
            "launch_nonce": launch_nonce, "namespace_values": namespace_values},
            p["proof_issuers"]["launch_attestation"], proof=True)
        resolution = self._sign({**common, "record_id": resolution_id, "record_type": "resolution",
            "issuer": p["record_issuers"]["resolution"], "nonce": _ref("nonce"), "issued_at": now,
            "predecessor_record_id": assignment_id, "predecessor_digest": assignment["integrity"]["content_digest"],
            "payload": {"requested_condition": condition, "resolved_condition": condition,
                "claim_namespaces": namespace_values, "resolver_version": p["resolver_version"],
                "fallback_used": False, "fallback_authorized": False, "authorization_ref": None,
                "launch_nonce": launch_nonce, "launch_attestation": launch}}, p["record_issuers"]["resolution"])
        _shape(assignment, "assignment", self._policy)
        _shape(launch, "launch_attestation", self._policy)
        _shape(resolution, "resolution", self._policy)
        prompt, generation = self._prompts[condition], self._generations[config]
        binding = ResolutionBinding(resolution_id, p["context_id"], self._policy.task_id,
            self._policy.task_version, self._catalog.task["task_span"], resource, condition, config,
            self._policy.bundle_map[resource][config], self._catalog.digest, _sha(prompt), _sha(generation),
            self._review, self._rights)
        assignment_raw, resolution_raw = canonical_json_bytes(assignment), canonical_json_bytes(resolution)
        self._used_invocations.add(request.invocation_ref)
        self._attempt_assignments[request.attempt_ref] = assignment_tuple
        self._publication_ordinals[request.attempt_ref] = request.publication_ordinal
        self._issued[_sha(assignment_raw)] = {"assignment": assignment_raw, "resolution": resolution_raw,
            "invocation_ref": request.invocation_ref, "attempt_ref": request.attempt_ref,
            "condition": condition, "episode_ref": request.episode.episode_ref,
            "resource": resource, "config": config}
        return HelpInputs(assignment_raw, resolution_raw, self._policy, prompt, generation,
                          self._catalog, binding, self._clock)

    def sign_outcome(self, request: OutcomeRequest) -> bytes:
        if type(request) is not OutcomeRequest:
            raise ContractError("typed outcome request required")
        now = self._now()
        entry = self._issued.get(_sha(request.assignment_raw))
        if (entry is None or entry["assignment"] != request.assignment_raw
                or entry["resolution"] != request.resolution_raw
                or entry["attempt_ref"] != request.attempt_ref
                or entry["episode_ref"] != request.episode.episode_ref
                or entry["resource"] != request.episode.logical_resource
                or entry["config"] != request.episode.config_id):
            raise ContractError("outcome assignment/resolution does not match issued help")
        exposure = self._verified_record(request.exposure_raw, "exposure")
        resolution = decode_json_object(entry["resolution"])
        common = self._common(request.attempt_ref)
        if (any(exposure.get(k) != v for k, v in common.items())
                or exposure.get("predecessor_record_id") != resolution["record_id"]
                or exposure.get("predecessor_digest") != resolution["integrity"]["content_digest"]
                or exposure.get("payload", {}).get("invocation_id") != entry["invocation_ref"]
                or exposure["payload"].get("enacted_condition") != entry["condition"]
                or exposure["payload"].get("artifact_version") != self._policy.bundle_map[entry["resource"]][entry["config"]]
                or not instant(resolution["issued_at"]) <= instant(exposure["issued_at"]) <= instant(now)):
            raise ContractError("outcome exposure identity/context differs")
        composite = request.outcome.get("composite", {})
        expected_composite = {"unit_token": request.attempt_ref,
            "experiment_id": common["experiment_id"], "experiment_version": common["experiment_version"],
            "exposure_record_id": exposure["record_id"],
            "exposure_digest": exposure["integrity"]["content_digest"], "purpose": request.purpose}
        if any(composite.get(k) != v for k, v in expected_composite.items()):
            raise ContractError("outcome selected-source composite differs")
        key = require_identifier(composite.get("outcome_key"), "outcome_key")
        if key in self._signed_outcomes:
            raise ContractError("outcome source key already signed")
        p = self._policy.profile
        if request.purpose not in p["permitted_purposes"]:
            raise ContractError("outcome purpose not permitted")
        record = {**common, "record_id": _ref("outcome"), "record_type": "outcome",
            "issuer": p["record_issuers"]["outcome"], "nonce": _ref("nonce"), "issued_at": now,
            "predecessor_record_id": exposure["record_id"],
            "predecessor_digest": exposure["integrity"]["content_digest"],
            "payload": {"exposure_record_id": exposure["record_id"],
                "exposure_digest": exposure["integrity"]["content_digest"],
                "attributed_condition": entry["condition"], "outcome_key": key,
                "consent_state": self._consent["state"], "consent_at": self._consent["at"],
                "consent_authority_ref": self._consent["authority_ref"],
                "consent_policy_version": self._consent["policy_version"],
                "purpose": request.purpose, "eligible": self._eligibility}}
        signed = self._sign(record, record["issuer"])
        _shape(signed, "outcome", self._policy)
        raw = canonical_json_bytes(signed)
        self._signed_outcomes.add(key)
        return raw

    def admission_context(self) -> AdmissionContext:
        return AdmissionContext(plain_json(self._policy.profile), self._policy.key_registry, self._now())
