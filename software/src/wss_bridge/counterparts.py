"""Shared neutral projection of stored arm outputs, with explicit local IO.

No native access, evaluation, score calculation or UF5 judgment occurs here.
All arms use this same projection and retain their own original decisions.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path, PurePosixPath
from collections.abc import Mapping

from .primitives import ContractError, canonical_json_bytes, plain_json, freeze_json
from .ledger import _real_directory, _read_file, _new_file, _fsync_directory

FORMAT = "wss-neutral-counterparts-v1"
ARMS = ("CPC_REFERENCE", "B0", "B2")
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_FILES = 10000
MAX_ROWS = 10000
SHARED = ("common native capture", "outcome/source ownership store", "declared policies",
          "trace/neutral projection machinery", "downstream join specification")
DESIGN = "CPC-WSS-WORKED-UF5-DENOMINATOR-V1-20261025"


def _check(ok, message):
    if not ok:
        raise ContractError("counterparts: " + message)


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _copy(value):
    return plain_json(value)


def _pointer(*parts):
    return "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def _locator(path, pointer=""):
    return {"path": "common/" + path, "json_pointer": pointer}


def _ref(value, *locators, state=None, reason=None):
    if state is None:
        state = "AVAILABLE" if value is not None else "MISSING"
    if state == "AVAILABLE":
        _check(bool(locators), "available field needs a concrete locator")
    else:
        reason = reason or "Not present in supplied evidence; no inferred replacement."
    return {"state": state, "value": _copy(value), "locators": list(locators), "reason": reason}


def _path(name):
    _check(type(name) is str and name and "\\" not in name, "invalid relative path")
    p = PurePosixPath(name)
    _check(not p.is_absolute() and str(p) == name and all(v not in (".", "..") for v in p.parts),
           "unsafe or noncanonical relative path")
    return p


def _json(raw):
    _check(type(raw) is bytes and len(raw) <= MAX_FILE, "bounded immutable JSON bytes required")
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result
        def finite(value):
            raise ValueError("nonfinite JSON number")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=finite)
    except (UnicodeError, ValueError) as exc:
        raise ContractError("counterparts: invalid JSON") from exc


def read_verified_inputs(root):
    """Read exactly manifest-listed closed runner files, never execute a project.

    This proves stored bytes match their supplied manifest, not native truth or
    authority. Paths, file kinds, aggregate size and producer links are bounded.
    """
    root = _real_directory(root, exists=True)
    raw_manifest = _read_file(root / "RUNNER_MANIFEST.json", MAX_FILE)
    manifest = _json(raw_manifest)
    _check(isinstance(manifest, dict) and manifest.get("format") == "wss-worked-runner-manifest-v1"
           and isinstance(manifest.get("files"), dict), "runner manifest shape")
    _check(len(manifest["files"]) <= MAX_FILES, "runner inventory count bound")
    raw_inputs, total = {}, len(raw_manifest)
    for name, entry in manifest["files"].items():
        p = _path(name)
        _check(isinstance(entry, dict) and set(entry) == {"sha256", "bytes"}
               and type(entry["bytes"]) is int and 0 <= entry["bytes"] <= MAX_FILE,
               "manifest entry shape/bound")
        total += entry["bytes"]
        _check(total <= MAX_TOTAL, "runner aggregate read bound")
        target = root.joinpath(*p.parts)
        _real_directory(target.parent, exists=True)
        raw = _read_file(target, MAX_FILE)
        _check(len(raw) == entry["bytes"] and _sha(raw) == entry["sha256"], "manifest bytes differ")
        raw_inputs[name] = raw
    raw_inputs["RUNNER_MANIFEST.json"] = raw_manifest
    for name in ("handoff_report.json", "controller_view.json", "episode_ledger.json"):
        _check(name in raw_inputs, "required supplied document missing: " + name)
    handoff = _json(raw_inputs["handoff_report.json"])
    return {"handoff_report": handoff, "terminal_controller_view": _json(raw_inputs["controller_view.json"]),
            "episode_ledger": _json(raw_inputs["episode_ledger.json"]),
            "producer_consumptions": _producer_consumptions(raw_inputs, handoff),
            "runner_start": _json(raw_inputs["STARTED.json"]) if "STARTED.json" in raw_inputs else None,
            "raw_inputs": raw_inputs}


def _producer_consumptions(raw_inputs, handoff):
    producer_consumptions = {}
    for name, raw in list(raw_inputs.items()):
        if not (name.startswith("producers/") and name.endswith("/reference-index/index.meta.json")):
            continue
        meta = _json(raw)
        _check(meta.get("format") == "wss-producer-reference-index-v1", "producer index format")
        invocation = meta.get("invocation_ref")
        _check(type(invocation) is str and invocation not in producer_consumptions, "duplicate producer invocation")
        stores = [s for s in handoff.get("inventory", {}).get("stores", [])
                  if s.get("role") == "PRODUCER" and s.get("store_ref") == meta.get("store_ref")]
        _check(len(stores) == 1, "producer index lacks one supplied inventory")
        refs = [r["reference"] for r in stores[0]["references"]
                if r.get("status") == "MATCH" and r["reference"]["snapshot_ref"].startswith("consume-manifest:")]
        _check(len(refs) <= 1, "ambiguous consume manifest")
        item = {"index_path": name, "metadata": meta, "consumption": None, "consumption_path": None}
        if refs:
            ref = refs[0]
            base = name.rsplit("/reference-index/index.meta.json", 1)[0]
            relative = base + "/snapshots/" + hashlib.sha256(ref["snapshot_ref"].encode()).hexdigest() + ".bin"
            _check(relative in raw_inputs, "consume reference bytes absent")
            b = raw_inputs[relative]
            _check(len(b) == ref["byte_length"] and _sha(b) == ref["sha256"], "consume reference mismatch")
            consumption = _json(b)
            _check(consumption.get("format") == "wss-consumption-v1"
                   and consumption.get("invocation_ref") == invocation, "consume owner mismatch")
            # Validate concrete captured-byte references, not just a role label.
            for key in ("prompt_reference", "generation_reference", "prompt_use_reference", "generation_use_reference"):
                capture = consumption[key]
                _check(capture["store_ref"] == meta["store_ref"], "foreign capture store")
                rel = base + "/snapshots/" + hashlib.sha256(capture["snapshot_ref"].encode()).hexdigest() + ".bin"
                _check(rel in raw_inputs and _sha(raw_inputs[rel]) == capture["sha256"]
                       and len(raw_inputs[rel]) == capture["byte_length"], "capture bytes mismatch")
            item.update(consumption=consumption, consumption_path=relative)
        producer_consumptions[invocation] = item
    return producer_consumptions


def _denominator(grain, members, arm, scope, basis, predicate, *, count=None, state="EXACT", reason=None):
    return {"grain": grain, "scope_ref": scope, "arm_or_shared": arm, "snapshot_basis": basis,
            "predicate": predicate, "member_refs": _copy(members), "count_state": state,
            "actual_count": len(members) if count is None and state == "EXACT" else count,
            "lower_bound": len(members) if state != "EXACT" else None, "reason": reason}


def project_counterparts(handoff_report, terminal_controller_view, episode_ledger, *,
                         common_inventory_ref="RUNNER_MANIFEST.json", producer_consumptions=None,
                         runner_start=None):
    """Pure shared projection from supplied stored objects; never evaluate/replay.

    Available means the supplied locator/value exists, not that its factual claim
    is independently certified. Missing/ambiguous mappings remain explicit.
    """
    h, terminal, episodes = _copy(handoff_report), _copy(terminal_controller_view), _copy(episode_ledger)
    consumers, start = _copy(producer_consumptions or {}), _copy(runner_start)
    _check(sum(len(canonical_json_bytes(v)) for v in (h, terminal, episodes, consumers, start)) <= MAX_TOTAL,
           "projection input bound")
    _path(common_inventory_ref)
    _check(h.get("format") == "wss-handoff-v1" and isinstance(episodes, list), "input formats")
    comparison, native, outcomes = h["ledgers"]["comparison"], h["ledgers"]["native"], h["ledgers"]["outcomes"]
    _check(set(comparison["arms"]) == set(ARMS), "three full-information arms required")
    _check(len(episodes) <= MAX_ROWS, "episode bound")
    for name in ("attempts", "operations", "opportunities", "ingestions", "occurrences", "invocations", "publications", "followups", "analyses"):
        _check(isinstance(native.get(name), dict) and len(native[name]) <= MAX_ROWS, "native table bound")
        _check(native["counts"][name] == len(native[name]), "native count differs")
    _check(terminal.get("context") == native.get("context"), "terminal context differs")
    for name in ("opportunities", "operations", "ingestions", "occurrences", "attempts", "invocations", "publications", "followups", "analyses"):
        _check(isinstance(terminal.get(name), dict) and len(terminal[name]) <= MAX_ROWS
               and terminal["counts"][name] == len(terminal[name]), "terminal view count/table differs")
    baseline_refs = None
    for arm in ARMS:
        a = comparison["arms"][arm]
        _check(a["method"] == arm and a["common_evidence_digest"] == h["common_evidence_digest"]
               and canonical_json_bytes(a["access_receipt"]) == canonical_json_bytes(h["access_receipt"]),
               "common evidence/access mismatch")
        result_refs = [(r["input_ref"], r["raw_digest"]) for r in a["results"]]
        if baseline_refs is None:
            baseline_refs = result_refs
        _check(result_refs == baseline_refs, "arm raw input scope differs")
        _check(len(a["results"]) <= MAX_ROWS and len(a["results"]) == len(a["join"]["core_ledger"]), "arm received scope")
        _check(a["join"]["cohort_ref"] == h["scope"]["cohort_ref"]
               and a["join"]["snapshot_ref"] == h["scope"]["snapshot_ref"], "arm snapshot scope differs")
        for result, row in zip(a["results"], a["join"]["core_ledger"]):
            _check(result["input_ref"] == row["input_ref"], "core row input identity differs")
            disposition = None if result["result"] is None else result["result"]["disposition"]
            _check(row["core_disposition"] == disposition, "original disposition differs")
            if result["result"] is not None:
                _check(result["result"].get("input_sha256") == result["raw_digest"], "original raw/result digest differs")
        ledger = a["join"]["core_ledger"]
        counts = a["join"]["counts"]
        _check(len({r["receipt_ref"] for r in ledger}) == len(ledger), "duplicate arm receipt identity")
        core_counts = Counter(r["core_disposition"] for r in ledger)
        _check(set(core_counts) <= {None, "ADMIT", "REJECT", "QUARANTINE", "ERROR_INPUT", "NOT_EVALUATED_CONFIG"}, "unknown core bucket")
        _check(counts["received_core"] == len(ledger) and counts["unresolved_core"] == core_counts[None]
               and counts["core_buckets"] == {k:core_counts[k] for k in ("ADMIT", "REJECT", "QUARANTINE", "ERROR_INPUT", "NOT_EVALUATED_CONFIG")},
               "stored core denominator contradicts rows")
        mapping_counts = Counter(r["mapping_status"] for r in ledger if r["core_disposition"] == "ADMIT")
        terminal_counts = Counter(r["primary_reason"] for r in ledger if r["core_disposition"] == "ADMIT" and r["mapping_status"] == "ELIGIBLE")
        _check(set(mapping_counts) <= {"PENDING", "HOLD", "ELIGIBLE"}
               and counts["admitted_mapping"] == {k:mapping_counts[k] for k in ("PENDING", "HOLD", "ELIGIBLE")}, "stored mapping denominator contradicts rows")
        terminals = ("JOINED", "ADMISSION_COMPOSITE_AMBIGUOUS", "EXTERNAL_COMPOSITE_AMBIGUOUS", "EXTERNAL_MISSING", "EXTERNAL_MEASURE_INVALID")
        _check(set(terminal_counts) <= set(terminals) and counts["eligible_terminals"] == {k:terminal_counts[k] for k in terminals}
               and counts["external_received"] == len(a["join"]["external_ledger"]), "stored terminal/external denominator contradicts rows")
    _check(len({e["episode_ref"] for e in episodes}) == len(episodes), "duplicate episode plan identity")
    _check(len({e["attempt_ref"] for e in episodes}) == len(episodes), "duplicate episode attempt identity")
    epi_by_attempt = {e["attempt_ref"]: (i, e) for i, e in enumerate(episodes)}
    context = native["context"]
    common_receipt = h["access_receipt"]
    output = {"format": FORMAT, "design_id": DESIGN, "shared_components": list(SHARED),
              "common_evidence_digest": h["common_evidence_digest"],
              "common_inventory_ref": "common/" + common_inventory_ref,
              "scope_authority": "SUPPLIED_EVIDENCE_ONLY", "UF5": "NOT_ADJUDICATED",
              "inherited_boundaries": h["boundaries"],
              "inspection_records": [], "scientific_or_release_approval": False,
              "four_D2_counterexamples": h["four_D2_counterexamples"], "arms": {}}
    source_doc = "handoff_report.json"
    for arm in ARMS:
        a = comparison["arms"][arm]
        arm_ptr = ("ledgers", "comparison", "arms", arm)
        scope = {"arm": arm, "run_ref": None, "cohort_ref": a["join"]["cohort_ref"],
                 "snapshot_ref": a["join"]["snapshot_ref"], "common_evidence_digest": h["common_evidence_digest"],
                 "common_inventory_ref": "common/" + common_inventory_ref,
                 "captured_prefix_head": h["scope"]["captured_head"], "basis_sequence": native["sequence"],
                 "current_analysis_ref": h["scope"]["native_analysis_ref"],
                 "terminal_view_ref": _locator("controller_view.json"),
                 "terminal_view_digest": _sha(canonical_json_bytes(terminal)),
                 "terminal_digest_basis": "Canonical JSON object digest; exact supplied file-byte digest is in common/RUNNER_MANIFEST.json.",
                 "terminal_basis_sequence": terminal.get("sequence"),
                 "terminal_delta_event_refs": _ref(None, state="UNRESOLVED", reason="View snapshots alone do not prove a complete event delta; inspect delivered controller journal."),
                 "captured_prefix_analyses": len(native["analyses"]),
                 "terminal_controller_analyses": len(terminal.get("analyses", {})),
                 "analysis_history_is_prefix_only": h["scope"]["analysis_history_is_prefix_only"]}
        # run_ref belongs to controller_scope, not an inferred suffix of cohort_ref.
        scopes = [d.get("controller_scope", {}) for d in outcomes["derivations"]]
        run_refs = {s.get("run_ref") for s in scopes if s.get("run_ref") is not None}
        scope["run_ref"] = next(iter(run_refs)) if len(run_refs) == 1 else None
        rows, crosswalk = [], []
        for i, (result, row) in enumerate(zip(a["results"], a["join"]["core_ledger"])):
            rp = _pointer(*arm_ptr, "join", "core_ledger", i)
            loc = _locator(source_doc, rp)
            composite = row.get("composite") or {}
            attempt_id = composite.get("unit_token")
            attempt = native["attempts"].get(attempt_id)
            episode_pair = epi_by_attempt.get(attempt_id)
            ep_index, episode = episode_pair if episode_pair else (None, None)
            owner = None if episode is None else episode.get("outcome_owner_invocation")
            calls = [(k, v) for k, v in native["invocations"].items() if v["attempt_ref"] == attempt_id]
            publications = [(k, p) for k, p in native["publications"].items() if any(p["invocation_ref"] == k1 for k1, _ in calls)]
            followed = None if attempt is None else native["followups"].get(attempt.get("selected_followup"))
            follow_id = None if attempt is None else attempt.get("selected_followup")
            task_occ_id = None if attempt is None else attempt.get("occurrence_key")
            fol_occ_id = None if followed is None else followed.get("occurrence_key")
            native_loc = lambda table, key: _locator(source_doc, _pointer("ledgers", "native", table, key))
            matching = [(j, o) for j, o in enumerate(outcomes["outcomes"]) if o.get("composite") == row.get("composite")]
            outcome = matching[0][1] if len(matching) == 1 else None
            op = None if outcome is None else outcome.get("lineage", {})
            outcome_loc = None if outcome is None else _locator(source_doc, _pointer("ledgers", "outcomes", "outcomes", matching[0][0]))
            consume = consumers.get(owner, {})
            cm = consume.get("consumption")
            cm_loc = None if cm is None else _locator(consume["consumption_path"])
            source_ordinal = None if episode is None else _locator("episode_ledger.json", _pointer(ep_index))
            raw_matches = [(batch_i, raw_i, raw_row) for batch_i, batch in enumerate(h["ledgers"].get("separate_adapter_batches", []))
                           for raw_i, raw_row in enumerate(batch.get("view", {}).get("rows", []))
                           if raw_row.get("input_ref") == result["input_ref"] and raw_row.get("raw_reference", {}).get("sha256") == result["raw_digest"]]
            raw_reference = raw_matches[0][2]["raw_reference"] if len(raw_matches) == 1 else None
            raw_locators = [] if len(raw_matches) != 1 else [_locator(source_doc, _pointer("ledgers", "separate_adapter_batches", raw_matches[0][0], "view", "rows", raw_matches[0][1], "raw_reference"))]
            nr = {"input_occurrence_ref": row["receipt_ref"], "input_ref": row["input_ref"],
                  "received_ordinal": i, "raw_input_ref": _ref(raw_reference, *raw_locators, state="AVAILABLE" if raw_reference else "UNRESOLVED", reason=None if raw_reference else "No unique supplied raw-reference mapping; original input ref/digest retained."),
                  "raw_input_digest": result["raw_digest"],
                  "attempt_ref": _ref(attempt_id, loc) if attempt_id is not None else _ref(None),
                  "task_occurrence_ref": _ref(native["occurrences"].get(task_occ_id), native_loc("occurrences", task_occ_id)) if task_occ_id else _ref(None),
                  "selected_followup_occurrence_ref": _ref(native["occurrences"].get(fol_occ_id), native_loc("occurrences", fol_occ_id)) if fol_occ_id else _ref(None),
                  "source_epoch_ref": _ref(context["source"], _locator(source_doc, _pointer("ledgers", "native", "context", "source"))),
                  "actor_context_ref": _ref(context["actor"], _locator(source_doc, _pointer("ledgers", "native", "context", "actor"))),
                  "item_version_ref": _ref({"task": context["task_target"], "followup": context["followup_target"], "task_version_ref": context["task_version_ref"]}, _locator(source_doc, _pointer("ledgers", "native", "context"))),
                  "presentation_ref": _ref({"task": context["task_target"].get("item_presentation_digest"), "followup": context["followup_target"].get("item_presentation_digest")}, _locator(source_doc, _pointer("ledgers", "native", "context"))),
                  "retained_native_value_ref": _ref(None if op is None else op.get("source_snapshot"), *([] if outcome_loc is None else [outcome_loc])),
                  "invocation_refs": _ref([v for _, v in calls], _locator(source_doc, _pointer("ledgers", "native", "invocations"))),
                  "all_publication_refs": _ref([v for _, v in publications], _locator(source_doc, _pointer("ledgers", "native", "publications"))),
                  "publication_status_refs": _ref([v for _, v in calls], _locator(source_doc, _pointer("ledgers", "native", "invocations"))),
                  "approved_bundle_ref": _ref(None if cm is None else cm["render_trace"].get("bundle_ref"), *([] if cm_loc is None else [cm_loc])),
                  "approved_config_ref": _ref(None if attempt is None else attempt["config_id"], *([] if attempt is None else [native_loc("attempts", attempt_id)])),
                  "actual_prompt_capture_ref": _ref(None if cm is None else cm["prompt_reference"], *([] if cm_loc is None else [cm_loc])),
                  "actual_generation_capture_ref": _ref(None if cm is None else cm["generation_reference"], *([] if cm_loc is None else [cm_loc])),
                  "final_exposure_ref": _ref({k: composite.get(k) for k in ("exposure_record_id", "exposure_digest")} if composite else None, loc),
                  "declared_component_refs": _ref({"measured_components": ["prompt", "generation"], "remaining_six": "DECLARED_NOT_UPGRADED"}, _locator(source_doc, "/boundaries")),
                  "source_owner_key": _ref(None if op is None else op.get("source_key"), *([] if outcome_loc is None else [outcome_loc])),
                  "serialization_owner_ref": _ref(owner, *([] if source_ordinal is None else [source_ordinal])),
                  "serialization_owner_ordinal": _ref(None if episode is None or owner not in episode["publication_invocations"] else episode["publication_invocations"].index(owner)+1, *([] if source_ordinal is None else [source_ordinal])),
                  "nonowner_publication_refs": _ref(None if episode is None else episode["unsubmitted_exposures"], *([] if source_ordinal is None else [source_ordinal])),
                  "recipe_ref": _ref(None if outcome is None else outcome.get("recipe_digest"), *([] if outcome_loc is None else [outcome_loc])),
                  "rubric_domain_ref": _ref(None if outcome is None else {k:outcome.get(k) for k in ("rubric_id", "rubric_version", "recipe_digest")}, *([] if outcome_loc is None else [outcome_loc])),
                  "external_received_refs": _ref(a["join"]["external_ledger"], _locator(source_doc, _pointer(*arm_ptr, "join", "external_ledger"))),
                  "outcome_measure_state": _ref(None if outcome is None else outcome.get("measure_state"), *([] if outcome_loc is None else [outcome_loc])),
                  "outcome_value": _ref(None if outcome is None else outcome.get("value"), *([] if outcome_loc is None else [outcome_loc])),
                  "original_arm_result_ref": _locator(source_doc, _pointer(*arm_ptr, "results", i)),
                  "core_disposition": row["core_disposition"],
                  "evaluation_state": "UNRESOLVED_API" if result["result"] is None else "RESULT_SUPPLIED",
                  "native_mapping_state": row.get("mapping_status"), "native_reason_flags": row.get("reason_flags", []),
                  "terminal_state": row.get("primary_reason"), "joined_value": row.get("value"),
                  "external_cardinality": row.get("external_multiplicity"), "admission_cardinality": row.get("admission_multiplicity"),
                  "original_core_row": row}
            rows.append(nr)
            for field, value in nr.items():
                if field == "original_core_row":
                    continue
                crosswalk.append({"canonical_table": "core_rows", "canonical_field": field,
                                  "row_ordinal": i, "original_arm": arm,
                                  "original_locator": value.get("locators", []) if isinstance(value, dict) and "locators" in value else [loc],
                                  "transform": "identity/reference projection; no evaluation, filtering or score calculation",
                                  "dependencies": ["common supplied native/outcome evidence", "original arm result"],
                                  "access_state": value.get("state", "AVAILABLE") if isinstance(value, dict) else "AVAILABLE",
                                  "verifier_route": "delivered common evidence inventory", "shared_components": list(SHARED)})
        source_only = []
        for ep_i, e in enumerate(episodes):
            for invocation in e.get("unsubmitted_exposures", []):
                call = native["invocations"].get(invocation)
                pubs = [p for p in native["publications"].values() if p["invocation_ref"] == invocation]
                source_only.append({"branch_ref": invocation, "branch_kind": "PUBLICATION_WITHOUT_COMPLETE_OUTCOME_CHAIN",
                    "attempt_ref": e["attempt_ref"], "invocation_ref": invocation,
                    "publication_ref": [p["publication_ref"] for p in pubs], "actual_status": None if call is None else call["stage"],
                    "no_chain_reason": "EXPLICIT_NONOWNER_RETAINED", "core_submission_state": "NOT_SUBMITTED",
                    "core_disposition": None, "evidence_refs": [_locator("episode_ledger.json", _pointer(ep_i)), native_loc("invocations", invocation)]})
        already = {s["invocation_ref"] for s in source_only}
        owners = {e.get("outcome_owner_invocation") for e in episodes}
        for invocation, call in native["invocations"].items():
            if invocation not in already and invocation not in owners:
                source_only.append({"branch_ref": invocation, "branch_kind": "INVOCATION_WITHOUT_DECLARED_COMPLETE_CHAIN",
                    "attempt_ref": call["attempt_ref"], "invocation_ref": invocation,
                    "publication_ref": [p["publication_ref"] for p in native["publications"].values() if p["invocation_ref"] == invocation],
                    "actual_status": call["stage"], "no_chain_reason": "NO_COMPLETE_CHAIN_OWNER_IN_SUPPLIED_EPISODE_LEDGER",
                    "core_submission_state": "NOT_SUBMITTED_IN_SUPPLIED_EPISODE_LEDGER", "core_disposition": None,
                    "evidence_refs": [native_loc("invocations", invocation)]})
        linked_attempts = {r["attempt_ref"]["value"] for r in rows if r["attempt_ref"]["value"] is not None}
        for attempt_id, attempt in native["attempts"].items():
            if attempt_id not in linked_attempts and not any(s["attempt_ref"] == attempt_id for s in source_only):
                source_only.append({"branch_ref": attempt_id, "branch_kind": "ATTEMPT_WITHOUT_RECEIVED_CORE_INPUT",
                    "attempt_ref": attempt_id, "invocation_ref": None, "publication_ref": [],
                    "actual_status": attempt["closure_status"], "no_chain_reason": "NO_RECEIVED_CORE_COMPOSITE_LINK",
                    "core_submission_state": "NOT_RECEIVED_IN_SUPPLIED_CORE_SCOPE", "core_disposition": None,
                    "evidence_refs": [native_loc("attempts", attempt_id)]})
        for op_id, operation in native["operations"].items():
            if operation["status"] in ("PENDING", "HELD"):
                source_only.append({"branch_ref": op_id, "branch_kind": "UNSETTLED_OR_HELD_NATIVE_OPERATION",
                    "attempt_ref": operation.get("attempt_ref"), "invocation_ref": None, "publication_ref": [],
                    "actual_status": operation["status"], "no_chain_reason": "ACTUAL_OPERATION_UNRESOLVED_OR_HELD",
                    "core_submission_state": "NOT_A_CORE_INPUT", "core_disposition": None,
                    "evidence_refs": [native_loc("operations", op_id)]})
        denominators = []
        for name in ("opportunities", "operations", "ingestions", "occurrences", "attempts", "invocations", "publications", "followups", "analyses"):
            denominators.append(_denominator("captured_prefix_"+name, list(native[name]), "SHARED", scope["cohort_ref"],
                {"kind":"CAPTURED_PREFIX", "sequence":native["sequence"]}, "members in supplied immutable-prefix view"))
        denominators.append(_denominator("terminal_controller_analyses", list(terminal.get("analyses", {})), "SHARED", scope["cohort_ref"],
            {"kind":"TERMINAL_CONTROLLER", "sequence":terminal.get("sequence")}, "members in separately supplied terminal view"))
        plans = None if start is None else start.get("configuration", {}).get("episodes")
        denominators.append(_denominator("episode_opportunities_planned", [] if plans is None else [e["episode_ref"] for e in plans], "SHARED", scope["cohort_ref"],
            "PROSPECTIVE_START_CONFIGURATION", "frozen planned episodes, not completed episode ledger", state="UNKNOWN" if plans is None else "EXACT",
            reason="STARTED configuration not supplied" if plans is None else None))
        for kind in ("TASK", "FOLLOWUP"):
            denominators.append(_denominator("controller_operations_"+kind, [k for k,v in native["operations"].items() if v["kind"]==kind], "SHARED", scope["cohort_ref"],
                {"kind":"CAPTURED_PREFIX", "sequence":native["sequence"]}, "actual durable operation IDs by kind"))
        for status in ("ADMIT", "REJECT", "QUARANTINE", "ERROR_INPUT", "NOT_EVALUATED_CONFIG", None):
            members = [r["input_occurrence_ref"] for r in rows if r["core_disposition"] == status]
            denominators.append(_denominator("received_core_"+(status or "UNRESOLVED_API"), members, arm, scope["cohort_ref"], scope["snapshot_ref"], "original arm core disposition identity partition"))
        denominators.append(_denominator("received_core_inputs", [r["input_occurrence_ref"] for r in rows], arm, scope["cohort_ref"], scope["snapshot_ref"], "all received arm input occurrences before filtering"))
        for status in ("PENDING", "HOLD", "ELIGIBLE"):
            denominators.append(_denominator("ADMIT_native_"+status, [r["input_occurrence_ref"] for r in rows if r["core_disposition"]=="ADMIT" and r["native_mapping_state"]==status], arm, scope["cohort_ref"], scope["snapshot_ref"], "original admitted native mapping partition"))
        for status in ("JOINED", "ADMISSION_COMPOSITE_AMBIGUOUS", "EXTERNAL_COMPOSITE_AMBIGUOUS", "EXTERNAL_MISSING", "EXTERNAL_MEASURE_INVALID"):
            denominators.append(_denominator("ELIGIBLE_terminal_"+status, [r["input_occurrence_ref"] for r in rows if r["core_disposition"]=="ADMIT" and r["native_mapping_state"]=="ELIGIBLE" and r["terminal_state"]==status], arm, scope["cohort_ref"], scope["snapshot_ref"], "original eligible terminal partition"))
        denominators.extend([
            _denominator("external_received_rows", [i for i,_ in enumerate(a["join"]["external_ledger"])], arm, scope["cohort_ref"], scope["snapshot_ref"], "all raw external row occurrences before filtering"),
            _denominator("outcome_derivations_received", [d["derivation_ref"] for d in outcomes["derivations"]], "SHARED", scope["cohort_ref"], scope["snapshot_ref"], "all supplied derivations including failed/pending"),
            _denominator("source_only_branches", [s["branch_ref"] for s in source_only], arm, scope["cohort_ref"], scope["snapshot_ref"], "retained branches without declared complete chain owner"),
            _denominator("actual_protocol_helper_calls", [], "SHARED", scope["cohort_ref"], scope["snapshot_ref"], "actual external process receipts required; envelopes do not establish launches", state="UNKNOWN", reason="Not inferred from ingestion/transport counts."),
        ])
        for table, records, locator in (
            ("scope", [scope], _locator(source_doc, "/scope")),
            ("source_only_rows", source_only, _locator(source_doc, "/ledgers/native")),
            ("denominator", denominators, _locator(source_doc, "/ledgers")),
        ):
            for ordinal, record in enumerate(records):
                for field in record:
                    locations = [locator]
                    if table == "scope":
                        locations = {
                            "arm": [_locator(source_doc, _pointer(*arm_ptr, "method"))],
                            "run_ref": [_locator(source_doc, "/ledgers/outcomes/derivations")],
                            "cohort_ref": [_locator(source_doc, "/scope/cohort_ref")],
                            "snapshot_ref": [_locator(source_doc, "/scope/snapshot_ref")],
                            "common_evidence_digest": [_locator(source_doc, "/common_evidence_digest")],
                            "common_inventory_ref": [_locator(common_inventory_ref)],
                            "captured_prefix_head": [_locator(source_doc, "/scope/captured_head")],
                            "basis_sequence": [_locator(source_doc, "/ledgers/native/sequence")],
                            "current_analysis_ref": [_locator(source_doc, "/scope/native_analysis_ref")],
                            "terminal_view_ref": [_locator("controller_view.json")],
                            "terminal_view_digest": [_locator("controller_view.json")],
                            "terminal_digest_basis": [_locator("controller_view.json")],
                            "terminal_basis_sequence": [_locator("controller_view.json", "/sequence")],
                            "terminal_delta_event_refs": [],
                            "captured_prefix_analyses": [_locator(source_doc, "/ledgers/native/analyses")],
                            "terminal_controller_analyses": [_locator("controller_view.json", "/analyses")],
                            "analysis_history_is_prefix_only": [_locator(source_doc, "/scope/analysis_history_is_prefix_only")],
                        }.get(field, [locator])
                    access = "UNRESOLVED" if record[field] is None or (isinstance(record[field], dict) and record[field].get("state") == "UNRESOLVED") else "AVAILABLE"
                    crosswalk.append({"canonical_table":table, "canonical_field":field, "row_ordinal":ordinal,
                        "original_arm":arm, "original_locator":locations,
                        "transform":"declared scope/reference/identity count projection; full member basis retained",
                        "dependencies":["delivered common evidence", "original arm scope"],
                        "access_state":access,
                        "verifier_route":"delivered common inventory; see source references and snapshot basis",
                        "shared_components":list(SHARED)})
        output["arms"][arm] = {"scope": scope, "core_rows": rows, "source_only_rows": source_only,
            "denominator": denominators, "field_crosswalk": crosswalk,
            "original_arm_output": a, "engine_receipt": a.get("engine_receipt"),
            "access_receipt": common_receipt, "shared_components": list(SHARED),
            "materialization_status": "STORED_EVIDENCE_PROJECTED_NOT_SCIENTIFICALLY_ADJUDICATED",
            "UF5": "NOT_ADJUDICATED", "inspection_records": [], "unresolved_dependencies": ["actual process/authority/rights provenance is not certified by this projection"]}
    _check(len(canonical_json_bytes(output)) <= MAX_TOTAL, "projection output bound")
    return freeze_json(output)


def write_counterparts(new_root, package, *, raw_inputs):
    """Explicit exclusive local materialization; all supplied common bytes copied.

    Never publish externally. Existing output leaves are refused, including retry.
    The caller retains this restricted output and separately supplies access rights.
    """
    data = _copy(package)
    _check(data.get("format") == FORMAT and set(data.get("arms", {})) == set(ARMS), "package shape")
    _check(isinstance(raw_inputs, Mapping) and len(raw_inputs) <= MAX_FILES+1, "common inventory bound")
    total = 0
    for name, raw in raw_inputs.items():
        _path(name)
        _check(type(raw) is bytes and len(raw) <= MAX_FILE, "bounded raw common bytes required")
        total += len(raw)
    _check(total <= MAX_TOTAL, "common write bound")
    for name in ("handoff_report.json", "controller_view.json", "episode_ledger.json", "RUNNER_MANIFEST.json"):
        _check(name in raw_inputs, "common source document missing")
    supplied_manifest = _json(raw_inputs["RUNNER_MANIFEST.json"])
    _check(supplied_manifest.get("format") == "wss-worked-runner-manifest-v1"
           and isinstance(supplied_manifest.get("files"), dict)
           and set(supplied_manifest["files"]) == set(raw_inputs)-{"RUNNER_MANIFEST.json"},
           "delivered common inventory differs from supplied runner manifest")
    for name, entry in supplied_manifest["files"].items():
        _check(isinstance(entry, dict) and set(entry) == {"bytes", "sha256"}
               and len(raw_inputs[name]) == entry["bytes"] and _sha(raw_inputs[name]) == entry["sha256"],
               "delivered common bytes differ from runner manifest")
    # Prevent a caller mixing a view from one input with delivered source bytes.
    h = _json(raw_inputs["handoff_report.json"])
    rebuilt = project_counterparts(h, _json(raw_inputs["controller_view.json"]), _json(raw_inputs["episode_ledger.json"]),
        producer_consumptions=_producer_consumptions(raw_inputs, h),
        runner_start=_json(raw_inputs["STARTED.json"]) if "STARTED.json" in raw_inputs else None,
        common_inventory_ref=data["common_inventory_ref"].removeprefix("common/"))
    _check(canonical_json_bytes(rebuilt) == canonical_json_bytes(data), "projection differs from delivered source objects")
    target = _real_directory(new_root, exists=False)
    target.mkdir(mode=0o700)
    _fsync_directory(target.parent)
    for name, raw in raw_inputs.items():
        p = target / "common" / name
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _new_file(p, raw)
    for arm in ARMS:
        d = target / arm
        d.mkdir(mode=0o700)
        for name in ("scope", "core_rows", "source_only_rows", "denominator", "field_crosswalk", "original_arm_output"):
            if name in {"core_rows", "source_only_rows", "denominator"}:
                _new_file(d / (name+".jsonl"), b"".join(canonical_json_bytes(row)+b"\n" for row in data["arms"][arm][name]))
            else:
                _new_file(d / (name+".json"), canonical_json_bytes(data["arms"][arm][name]))
    _new_file(target / "COUNTERPARTS.json", canonical_json_bytes(data))
    _new_file(target / "BOUNDARIES.json", canonical_json_bytes({"UF5":"NOT_ADJUDICATED", "scientific_or_release_approval":False,
        "projection_shared_by_all_arms":True, "native_execution":False,
        "four_D2_counterexamples":data["four_D2_counterexamples"], "common_input_bytes_preserved":True}))
    manifest = {str(p.relative_to(target)):{"bytes":p.stat().st_size,"sha256":_sha(p.read_bytes())}
                for p in sorted(target.rglob("*")) if p.is_file()}
    _new_file(target / "MANIFEST.json", canonical_json_bytes({"format":FORMAT+"-manifest", "files":manifest}))
    for d in sorted((p for p in target.rglob("*") if p.is_dir()), key=lambda p:len(p.parts), reverse=True):
        _fsync_directory(d)
    _fsync_directory(target)
    return freeze_json({"status":"MATERIALIZED_STORED_EVIDENCE_ONLY", "files":len(manifest),
                        "UF5":"NOT_ADJUDICATED", "scientific_or_release_approval":False})


def materialize_counterparts(existing_runner_root, new_root):
    """Convenience read/hash/project/write boundary; no native or core execution."""
    inputs = read_verified_inputs(existing_runner_root)
    raw = inputs.pop("raw_inputs")
    package = project_counterparts(**inputs)
    receipt = write_counterparts(new_root, package, raw_inputs=raw)
    return package, receipt
