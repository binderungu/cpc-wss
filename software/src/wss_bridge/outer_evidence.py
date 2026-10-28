"""Read-only binding of outer acquisition receipts to offline counterpart bytes.

Import/construction performs no IO. Materialization only reads a frozen supplied
manifest and writes an unused local directory. No native access or UF5 judgment.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath

from .ledger import _real_directory, _read_file, _new_file, _fsync_directory
from .primitives import ContractError, canonical_json_bytes

FORMAT = "wss-outer-acquisition-inputs-v1"
OUTPUT_FORMAT = "wss-outer-evidence-handoff-v1"
MANIFEST_NAME = "OUTER_EVIDENCE_MANIFEST.json"
MODES = {"SYNTHETIC_OFFLINE_QUALIFICATION", "BOUNDED_NATIVE_ACQUISITION"}
ARMS = ("CPC_REFERENCE", "B0", "B2")
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_FILES = 20000
HASH_RE = re.compile(r"sha256:[0-9a-f]{64}")


class OuterEvidenceError(ContractError):
    """Malformed/inconsistent stored input, never a core/scientific disposition."""


def _check(condition, reason):
    if not condition:
        raise OuterEvidenceError("outer evidence: " + reason)


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _decode(raw):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate key")
            obj[key] = value
        return obj
    def finite(value):
        raise ValueError("nonfinite constant")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=finite)
    except (UnicodeError, ValueError) as exc:
        raise OuterEvidenceError("outer evidence: invalid JSON") from exc


def _relative(value):
    _check(type(value) is str and value and "\\" not in value, "invalid relative path")
    p = PurePosixPath(value)
    _check(not p.is_absolute() and str(p) == value and not any(v in {".", ".."} for v in p.parts),
           "path traversal or noncanonical path")
    return p


def _loc(path, pointer=""):
    return {"path": "common/" + path, "json_pointer": pointer}


def _record_count(grain, known, unknown, *, basis, predicate):
    return {"grain": grain, "arm_or_shared": "SHARED_ALL_THREE_ARMS", "snapshot_basis": basis,
            "predicate": predicate, "member_refs": known, "unknown_member_refs": unknown,
            "count_state": "EXACT" if not unknown else "PARTIAL_UNKNOWN",
            "actual_count": len(known) if not unknown else None,
            "lower_bound": len(known) if unknown else None,
            "reason": None if not unknown else "Missing/ambiguous receipts or fields prevent an exact count; no zero imputation."}


def _inventory(root, relative, listed, gaps):
    """Dedicated event/process roots must not hide unlisted actual files."""
    directory = root.joinpath(*_relative(relative).parts)
    if not directory.exists():
        gaps.append({"kind":"MISSING_DEDICATED_ROOT", "path":relative})
        return
    _real_directory(directory, exists=True)
    seen = 0
    for p in directory.rglob("*"):
        seen += 1
        _check(seen <= MAX_FILES, "dedicated inventory bound")
        _check(not p.is_symlink(), "dedicated receipt path is symlink")
        if p.is_dir():
            continue
        name = p.relative_to(root).as_posix()
        # Missing-from-snapshot evidence is retained as an explicit gap. Never
        # read its contents or infer that it was a zero-attempt operation.
        if name not in listed:
            gaps.append({"kind":"UNLISTED_DEDICATED_RECEIPT", "path":name})


def _bind_inner(raws, inner_path, root_ref, expected_format, gaps):
    if inner_path not in raws:
        gaps.append({"kind":"MISSING_INNER_MANIFEST", "path":inner_path})
        return None
    inner = _decode(raws[inner_path])
    _check(isinstance(inner, dict) and inner.get("format") == expected_format
           and isinstance(inner.get("files"), dict), "inner manifest shape/format")
    for name, item in inner["files"].items():
        _relative(name)
        _check(isinstance(item, dict) and set(item) == {"bytes", "sha256"}
               and type(item["bytes"]) is int and 0 <= item["bytes"] <= MAX_FILE
               and type(item["sha256"]) is str and HASH_RE.fullmatch(item["sha256"]),
               "inner manifest entry")
        outer_name = root_ref + "/" + name
        if outer_name not in raws:
            gaps.append({"kind":"MISSING_INNER_PAYLOAD_BINDING", "path":outer_name})
        else:
            _check(len(raws[outer_name]) == item["bytes"] and _sha(raws[outer_name]) == item["sha256"],
                   "inner manifest payload mismatch")
    return {"path":inner_path, "sha256":_sha(raws[inner_path]), "bytes":len(raws[inner_path]),
            "declared_payloads":len(inner["files"]), "locator":_loc(inner_path)}


def _index(root):
    raw_manifest = _read_file(root / MANIFEST_NAME, MAX_FILE)
    m = _decode(raw_manifest)
    required = {"format", "mode", "files", "runner_root", "counterpart_root", "grant_ref", "preflight_ref",
                "event_root", "process_root", "child_exit_code", "parent_status"}
    _check(isinstance(m, dict) and set(m) == required and m["format"] == FORMAT and m["mode"] in MODES,
           "closed outer manifest schema/mode")
    _check(m["child_exit_code"] is None or type(m["child_exit_code"]) is int, "child exit code type")
    _check(m["parent_status"] in {"COMPLETED", "FAILED"}, "parent status")
    for key in ("runner_root", "counterpart_root", "grant_ref", "preflight_ref", "event_root", "process_root"):
        _relative(m[key])
    roots = [m[k] for k in ("runner_root", "counterpart_root", "event_root", "process_root")]
    _check(all(a != b and not a.startswith(b+"/") and not b.startswith(a+"/")
               for i,a in enumerate(roots) for b in roots[i+1:]), "dedicated roots overlap")
    _check(isinstance(m["files"], dict) and len(m["files"]) <= MAX_FILES
           and MANIFEST_NAME not in m["files"], "outer inventory bound/self-reference")
    total, raws, gaps = len(raw_manifest), {}, []
    for name, item in m["files"].items():
        path = _relative(name)
        _check("private" not in path.parts and not name.endswith(".command.private.json"),
               "private command/credential payload is outside outer public evidence scope")
        _check(isinstance(item, dict) and set(item) == {"bytes", "sha256"}
               and type(item["bytes"]) is int and 0 <= item["bytes"] <= MAX_FILE
               and type(item["sha256"]) is str and HASH_RE.fullmatch(item["sha256"]), "outer payload entry")
        total += item["bytes"]
        _check(total <= MAX_TOTAL, "aggregate outer input bound")
        p = root.joinpath(*path.parts)
        _real_directory(p.parent, exists=True)
        raw = _read_file(p, MAX_FILE)
        _check(len(raw) == item["bytes"] and _sha(raw) == item["sha256"], "outer payload hash/size mismatch")
        raws[name] = raw
    for key in ("event_root", "process_root"):
        _inventory(root, m[key], set(raws), gaps)
    inner_runner = _bind_inner(raws, m["runner_root"]+"/RUNNER_MANIFEST.json", m["runner_root"],
                               "wss-worked-runner-manifest-v1", gaps)
    inner_counterpart = _bind_inner(raws, m["counterpart_root"]+"/MANIFEST.json", m["counterpart_root"],
                                    "wss-neutral-counterparts-v1-manifest", gaps)
    if inner_runner is not None:
        copied = m["counterpart_root"]+"/common/RUNNER_MANIFEST.json"
        if copied not in raws:
            gaps.append({"kind":"MISSING_COUNTERPART_COMMON_RUNNER_MANIFEST", "path":copied})
        else:
            _check(raws[copied] == raws[inner_runner["path"]], "counterpart common runner manifest differs")
    for key in ("grant_ref", "preflight_ref"):
        if m[key] not in raws:
            gaps.append({"kind":"MISSING_"+key.upper(), "path":m[key]})
    raws[MANIFEST_NAME] = raw_manifest
    return m, raws, gaps, inner_runner, inner_counterpart


def _project(m, raws, gaps, runner_binding, counterpart_binding):
    basis = {"outer_manifest_sha256":_sha(raws[MANIFEST_NAME]), "mode":m["mode"]}
    events, intents, processes = [], {}, {}
    event_prefix, process_prefix = m["event_root"]+"/", m["process_root"]+"/"
    index = []
    for name, raw in raws.items():
        role = "OTHER_LISTED_INPUT"
        if name == m["grant_ref"]: role = "AUTHORITY_DECLARATION"
        elif name == m["preflight_ref"]: role = "PREFLIGHT_DECLARATION"
        elif name.startswith(m["runner_root"]+"/"): role = "INNER_RUNNER_EVIDENCE"
        elif name.startswith(m["counterpart_root"]+"/"): role = "INNER_COUNTERPART_EVIDENCE"
        elif name.startswith(event_prefix) and name.endswith(".json"):
            e = _decode(raw)
            _check(isinstance(e, dict) and type(e.get("kind")) is str and isinstance(e.get("data"), dict), "event envelope shape")
            if not any(k in e for k in ("time", "time_utc", "UTC", "utc", "recorded_UTC", "recorded_monotonic_ns", "monotonic_ns")):
                gaps.append({"kind":"EVENT_TIME_UNAVAILABLE", "path":name})
            events.append({"path":name, "event":e, "locator":_loc(name)})
            role = "OUTER_ACQUISITION_EVENT"
        elif name.startswith(process_prefix):
            if re.fullmatch(r"read-\d+\.intent\.json", name[len(process_prefix):]):
                role="HELPER_LAUNCH_CHARGE_INTENT"; intents[name] = _decode(raw)
                _check(not isinstance(intents[name].get("command"), list)
                       and not isinstance(intents[name].get("argv"), list), "public intent contains private argv")
            elif re.fullmatch(r"read-\d+\.process\.json", name[len(process_prefix):]):
                role="HELPER_PROCESS_TERMINAL_RECEIPT"; processes[name] = _decode(raw)
            elif name.endswith(".stdout.bin"): role="HELPER_RAW_STDOUT"
            elif name.endswith(".failure.json"): role="HELPER_FAILURE_RECEIPT"
            elif name.endswith(".cleanup.json"): role="HELPER_CLEANUP_RECEIPT"
        index.append({"path":name, "role":role, "bytes":len(raw), "sha256":_sha(raw), "locator":_loc(name),
                      "integrity":"MATCH_SUPPLIED_FROZEN_MANIFEST", "truth_or_authority_certified":False})
    events.sort(key=lambda e:e["path"])
    by_kind = {}
    for e in events:
        by_kind.setdefault(e["event"]["kind"], []).append(e)
    def event_members(kind): return [{"path":e["path"], "operation_ref":e["event"]["data"].get("operation_ref"),
                                    "locator":e["locator"]} for e in by_kind.get(kind, [])]
    submit_events = by_kind.get("SUBMIT_INTENT_DURABLE", [])
    read_events = by_kind.get("READ_INTENT_DURABLE", [])
    native_returns = by_kind.get("ORDINARY_NATIVE_RETURN", [])
    submits = {}
    for e in submit_events:
        d=e["event"]["data"]; op=d.get("operation_ref")
        if type(op) is not str or d.get("kind") not in {"TASK", "FOLLOWUP"} or op in submits:
            gaps.append({"kind":"SUBMIT_OPERATION_IDENTITY_AMBIGUOUS", "path":e["path"]})
        else: submits[op] = e
    returned, unresolved_return = {}, []
    for e in native_returns:
        d=e["event"]["data"]; op=d.get("operation_ref")
        if op not in submits or op in returned or type(d.get("known")) is not bool:
            unresolved_return.append(e["path"])
            gaps.append({"kind":"RETURN_OPERATION_BINDING_UNAVAILABLE", "path":e["path"]})
        else: returned[op] = e
    by_ordinal, ambiguous_read_events = {}, []
    for e in read_events:
        d=e["event"]["data"]; n=d.get("read_ordinal")
        if type(n) is not int or n < 1 or n in by_ordinal or type(d.get("operation_ref")) is not str:
            ambiguous_read_events.append(e["path"])
            gaps.append({"kind":"READ_REQUEST_IDENTITY_AMBIGUOUS", "path":e["path"]})
        else: by_ordinal[n] = e
    intent_by_n, proc_by_n = {}, {}
    for collection, dest, label in ((intents,intent_by_n,"INTENT"),(processes,proc_by_n,"PROCESS")):
        for path, record in collection.items():
            _check(isinstance(record, dict), "process/intent record shape")
            n=record.get("read_ordinal")
            filename_n=int(path.rsplit("/read-",1)[1].split(".",1)[0])
            _check(type(n) is int and n == filename_n and n > 0, "read ordinal/filename contradiction")
            _check(n not in dest, "duplicate read receipt identity")
            dest[n] = (path,record)
    read_index, all_read_ids = [], sorted(set(by_ordinal)|set(intent_by_n)|set(proc_by_n))
    for n in all_read_ids:
        request=by_ordinal.get(n); intent=intent_by_n.get(n); process=proc_by_n.get(n)
        paths=[e[0] for e in (intent,process) if e is not None]+([] if request is None else [request["path"]])
        row={"read_ordinal":n, "request_ref":None if request is None else request["path"],
             "launch_intent_ref":None if intent is None else intent[0], "process_ref":None if process is None else process[0],
             "operation_ref":None, "slot_ms":None, "process_started":None, "popen_attempted":None,
             "charged_launch_attempt":None, "close_state":None, "returncode":None,
             "evidence_state":"INDEXED_RECEIPTS_ONLY", "gaps":[], "locators":[_loc(p) for p in paths]}
        candidates=[]
        if request:candidates.append(request["event"]["data"])
        if intent:candidates.append(intent[1])
        if process:candidates.append(process[1])
        for key in ("operation_ref", "slot_ms"):
            values=[r.get(key) for r in candidates]
            known_values=[v for v in values if v is not None]
            _check(len({json.dumps(v,sort_keys=True) for v in known_values}) <= 1, "read operation/slot contradiction")
            row[key]=known_values[0] if known_values else None
            if not values or any(v is None for v in values):row["gaps"].append(key.upper()+"_BINDING_UNAVAILABLE")
        if request is None:row["gaps"].append("PARENT_BUDGET_CHARGE_REQUEST_MISSING")
        if intent is None:row["gaps"].append("HELPER_LAUNCH_CHARGE_INTENT_MISSING")
        if process is None:row["gaps"].append("HELPER_PROCESS_RECEIPT_MISSING")
        else:
            proc=process[1]
            for key in ("process_started", "popen_attempted", "charged_launch_attempt"):
                if type(proc.get(key)) is bool:row[key]=proc[key]
                else:row["gaps"].append(key.upper()+"_UNKNOWN")
            row["close_state"],row["returncode"]=proc.get("close_state"),proc.get("returncode")
            if row["process_started"] is True:
                if row["popen_attempted"] is not True:raise OuterEvidenceError("outer evidence: started process without Popen attempt")
                if row["close_state"] not in {"CONFIRMED", "UNCONFIRMED"}:row["gaps"].append("CLOSE_STATE_UNKNOWN")
            elif row["process_started"] is False and proc.get("close_confirmed") is True:
                raise OuterEvidenceError("outer evidence: unstarted process cannot confirm read close")
            if row["charged_launch_attempt"] is False:
                raise OuterEvidenceError("outer evidence: terminal launch receipt contradicts charge")
            if row["close_state"] == "CONFIRMED":
                _check(proc.get("close_confirmed") is True and row["process_started"] is True
                       and proc.get("returncode") == 0 and proc.get("timeout_or_limit") is False,
                       "close-confirmed receipt contradicts terminal process state")
            if proc.get("stdout_file_present") is True:
                stdout=process[0].removesuffix(".process.json")+".stdout.bin"
                if stdout not in raws:row["gaps"].append("RAW_STDOUT_UNAVAILABLE")
                else:_check(_sha(raws[stdout]) == proc.get("stdout_sha256") and len(raws[stdout]) == proc.get("stdout_bytes"), "process stdout hash/size contradiction")
            elif proc.get("stdout_file_present") is not False:
                row["gaps"].append("STDOUT_PRESENCE_UNKNOWN")
            elif row["process_started"] is True:
                row["gaps"].append("RAW_STDOUT_ABSENT_FOR_STARTED_PROCESS")
        if row["gaps"]:
            row["evidence_state"]="NOT_ASSESSABLE"
            gaps.append({"kind":"READ_RECEIPT_GAPS", "read_ordinal":n, "reasons":row["gaps"]})
        read_index.append(row)
    if not events:gaps.append({"kind":"NO_OUTER_EVENT_RECEIPTS", "path":m["event_root"]})
    if not read_index:gaps.append({"kind":"NO_HELPER_READ_RECEIPTS", "path":m["process_root"]})
    unknown_completions=[{"operation_ref":op,"locator":_loc(e["path"])} for op,e in submits.items()
                         if op not in returned or not returned[op]["event"]["data"]["known"]]
    denominators=[]
    no_events=[] if events else [{"missing":"event scope"}]
    unknown_submit_bindings=unresolved_return+[{"operation_ref":r["operation_ref"],"reason":"helper operation lacks a submit-intent binding"} for r in read_index if r["operation_ref"] not in submits]
    denominators.append(_record_count("native_submit_budget_charged",event_members("SUBMIT_INTENT_DURABLE"),no_events+unknown_submit_bindings,basis=basis,predicate="durable parent submit intent; not proof of bytes sent or success"))
    for kind in ("TASK","FOLLOWUP"):
        members=[{"operation_ref":op,"locator":e["locator"]} for op,e in submits.items() if e["event"]["data"]["kind"]==kind]
        denominators.append(_record_count("native_submit_budget_charged_"+kind,members,no_events+unknown_submit_bindings,basis=basis,predicate="durable parent submit intent kind"))
    denominators.append(_record_count("native_completion_known",[{"operation_ref":op,"locator":e["locator"]} for op,e in returned.items() if e["event"]["data"]["known"]],unknown_completions+unresolved_return+no_events,basis=basis,predicate="explicit operation-bound ordinary return known=true; unreturned attempts remain unresolved"))
    denominators.append(_record_count("native_completion_unresolved",unknown_completions,unresolved_return+no_events,basis=basis,predicate="charged attempts without known=true completion; this includes unknown returns and missing returns"))
    missing_read_requests=[{"read_ordinal":r["read_ordinal"],"reason":"process/launch evidence lacks parent request"} for r in read_index if r["request_ref"] is None]
    denominators.append(_record_count("protocol_read_budget_charged_requests",event_members("READ_INTENT_DURABLE"),ambiguous_read_events+no_events+missing_read_requests,basis=basis,predicate="parent charged request, distinct from helper launch attempt or successful process"))
    missing_reads=[] if read_index else [{"missing":"read receipts"}]
    charge_known=[{"read_ordinal":n,"intent_ref":path} for n,(path,_) in intent_by_n.items()]
    charge_unknown=[{"read_ordinal":r["read_ordinal"],"reason":"durable helper launch-charge intent unavailable"} for r in read_index if r["launch_intent_ref"] is None]
    denominators.append(_record_count("helper_launch_budget_charges",charge_known,charge_unknown+missing_reads,basis=basis,predicate="durable helper launch-charge intent, written before Popen; no successful-process inference"))
    for field,grain in (("popen_attempted","helper_Popen_attempts"),("process_started","helper_processes_confirmed_started")):
        known=[{"read_ordinal":r["read_ordinal"],"process_ref":r["process_ref"]} for r in read_index if r[field] is True]
        unknown=[{"read_ordinal":r["read_ordinal"],"reason":field+" unavailable"} for r in read_index if r[field] is None]
        denominators.append(_record_count(grain,known,unknown+missing_reads,basis=basis,predicate="explicit actual process receipt flag "+field+"; never inferred from ingestions"))
    for state,grain in (("CONFIRMED","started_process_close_confirmed"),("UNCONFIRMED","started_process_close_unconfirmed"),("NOT_STARTED","helper_receipt_not_started")):
        known=[{"read_ordinal":r["read_ordinal"],"process_ref":r["process_ref"]} for r in read_index if r["close_state"]==state]
        unknown=[{"read_ordinal":r["read_ordinal"],"reason":"close state unavailable"} for r in read_index if r["close_state"] not in {"CONFIRMED","UNCONFIRMED","NOT_STARTED"}]
        denominators.append(_record_count(grain,known,unknown+missing_reads,basis=basis,predicate="explicit close_state; forced cleanup is not read close"))
    incomplete_scope=[g for g in gaps if g["kind"] in {"UNLISTED_DEDICATED_RECEIPT","MISSING_DEDICATED_ROOT"}]
    if incomplete_scope:
        for count in denominators:
            count["unknown_member_refs"].extend(incomplete_scope)
            count["lower_bound"]=len(count["member_refs"])
            count["actual_count"]=None
            count["count_state"]="PARTIAL_UNKNOWN"
            count["reason"]="Dedicated receipt inventory is incomplete; known listed members are only a lower bound."
    # A supplied class/mode never supplies truthful native observation or rights.
    grant=None if m["grant_ref"] not in raws else _decode(raws[m["grant_ref"]])
    preflight=None if m["preflight_ref"] not in raws else _decode(raws[m["preflight_ref"]])
    if m["mode"] == "BOUNDED_NATIVE_ACQUISITION" and (not isinstance(grant,dict) or grant.get("native_execution_authorized") is not True):
        gaps.append({"kind":"NATIVE_AUTHORITY_DECLARATION_NOT_TRUE", "path":m["grant_ref"]})
    prefix_relation=_prefix_relation(m,raws)
    crosswalk=[{"outer_field":"grant_declaration", "locators":[] if grant is None else [_loc(m["grant_ref"])], "state":"MISSING" if grant is None else "SUPPLIED_DECLARATION_ONLY"},
               {"outer_field":"preflight_declaration", "locators":[] if preflight is None else [_loc(m["preflight_ref"])], "state":"MISSING" if preflight is None else "SUPPLIED_DECLARATION_ONLY"},
               {"outer_field":"child_exit_code", "locators":[_loc(MANIFEST_NAME,"/child_exit_code")], "state":"UNRESOLVED" if m["child_exit_code"] is None else "STORED_REPORTED_EXIT"},
               {"outer_field":"parent_status", "locators":[_loc(MANIFEST_NAME,"/parent_status")], "state":"STORED_REPORTED_STATUS"},
               {"outer_field":"native_submit_attempts", "locators":[e["locator"] for e in submit_events], "state":"NOT_ASSESSABLE" if not submit_events else "DURABLE_CHARGE_RECORDS"},
               {"outer_field":"ordinary_HTTP_completion", "locators":[e["locator"] for e in native_returns], "state":"NOT_ASSESSABLE" if unknown_completions or unresolved_return or not native_returns else "STORED_OPERATION_BOUND_RETURN"},
               {"outer_field":"helper_processes_and_raw", "locators":[loc for r in read_index for loc in r["locators"]], "state":"NOT_ASSESSABLE" if any(r["gaps"] for r in read_index) or not read_index else "STORED_PROCESS_RECEIPTS"},
               {"outer_field":"prefix_terminal_relation", **prefix_relation}]
    return {"format":OUTPUT_FORMAT, "supplied_evidence_class":m["mode"], "outer_manifest_binding":basis,
            "integrity":"ALL_LISTED_PAYLOAD_BYTES_MATCH", "evidence_assessment":"NOT_ASSESSABLE" if gaps else "ASSESSABLE_STORED_RECEIPTS_ONLY",
            "gaps":gaps, "runner_binding":runner_binding, "counterpart_binding":counterpart_binding,
            "authority_and_preflight":{"grant":grant,"preflight":preflight,"independent_authority_or_rights_certification":False},
            "execution_status":{"parent_status":m["parent_status"],"child_exit_code":m["child_exit_code"]},
            "index":index, "outer_events":events, "helper_read_index":read_index,
            "denominator_additions":denominators,"crosswalk":crosswalk,
            "arms":{arm:{"same_outer_snapshot_digest":basis["outer_manifest_sha256"],"shared":True,"crosswalk":"OUTER_CROSSWALK.json","denominator":"OUTER_DENOMINATOR.json"} for arm in ARMS},
            "boundaries":{"UF5":"NOT_ADJUDICATED","inspection_results":[],"native_access_in_this_module":False,
                          "native_truth_independently_verified":False,"rights_or_public_release_authorized":False,
                          "inner_labels":"PRESERVED_UNCHANGED; outer receipts do not relabel offline computation as native execution",
                          "source_only":"Preserved in byte-exact inner counterpart payloads; never fabricated as core verdicts"}}


def _prefix_relation(m,raws):
    """Recount stored analysis events only; no controller replay/evaluation."""
    view_path=m["runner_root"]+"/controller_view.json"
    counterpart_path=m["counterpart_root"]+"/COUNTERPARTS.json"
    journal_path=m["runner_root"]+"/controller/journal/entries.jsonl"
    result={"state":"UNRESOLVED_EVENT_DELTA","locators":[_loc(view_path),_loc(counterpart_path),_loc(journal_path)],
            "reason":"No adequate stored journal/snapshot identity basis; no fixed plus-one correction.","delta_events":[]}
    if any(p not in raws for p in (view_path,counterpart_path,journal_path)):return result
    view,cp=_decode(raws[view_path]),_decode(raws[counterpart_path])
    scopes=[cp.get("arms",{}).get(a,{}).get("scope") for a in ARMS]
    if any(not isinstance(s,dict) for s in scopes):return result
    keys=("basis_sequence","captured_prefix_analyses","terminal_controller_analyses","current_analysis_ref")
    if any(any(s.get(k)!=scopes[0].get(k) for k in keys) for s in scopes[1:]):return result
    basis=scopes[0].get("basis_sequence")
    if type(basis) is not int:return result
    lines=raws[journal_path].splitlines()
    if len(lines)>MAX_FILES:return result
    entries=[_decode(line) for line in lines]
    if [e.get("sequence") for e in entries]!=list(range(1,len(entries)+1)):return result
    if view.get("sequence")!=len(entries) or not 0<=basis<=len(entries):return result
    analyses=[]
    for e in entries:
        payload=e.get("record",{}).get("payload",{})
        if payload.get("event")=="ANALYSIS":
            ref=payload.get("data",{}).get("analysis_ref")
            if type(ref) is not str:return result
            analyses.append((e["sequence"],ref))
    prefix=[ref for seq,ref in analyses if seq<=basis]
    all_refs=[ref for _,ref in analyses]
    delta=[{"sequence":e["sequence"],"event":e.get("record",{}).get("payload",{}).get("event"),
            "record_ref":e.get("record",{}).get("record_ref"),"locator":{"path":"common/"+journal_path,"jsonl_line":e["sequence"]}}
           for e in entries if e["sequence"]>basis]
    if (len(prefix)!=scopes[0].get("captured_prefix_analyses") or len(all_refs)!=scopes[0].get("terminal_controller_analyses")
            or set(all_refs)!=set(view.get("analyses",{})) or len(all_refs)!=len(set(all_refs))
            or scopes[0].get("current_analysis_ref") not in [ref for seq,ref in analyses if seq>basis]):return result
    return {"state":"BOUND_STORED_EVENT_DELTA","locators":result["locators"],"reason":"Stored manifest-bound journal identities/counts reconcile; not controller replay or independent source truth.",
            "prefix_analysis_count":len(prefix),"terminal_analysis_count":len(all_refs),"basis_sequence":basis,"terminal_sequence":view["sequence"],"delta_events":delta}


def materialize_outer_handoff(campaign_root, new_root):
    """Verify a supplied snapshot, index receipts, write an exclusive local view."""
    source=_real_directory(campaign_root,exists=True)
    m,raws,gaps,runner_binding,counterpart_binding=_index(source)
    report=_project(m,raws,gaps,runner_binding,counterpart_binding)
    target=_real_directory(new_root,exists=False)
    _check(len(canonical_json_bytes(report)) <= MAX_TOTAL,"outer report bound")
    target.mkdir(mode=0o700);_fsync_directory(target.parent)
    for name,raw in raws.items():
        path=target/"common"/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);_new_file(path,raw)
    for name,value in (("OUTER_HANDOFF.json",report),("OUTER_INDEX.json",report["index"]),
                       ("OUTER_CROSSWALK.json",report["crosswalk"]),("OUTER_DENOMINATOR.json",report["denominator_additions"])):
        _new_file(target/name,canonical_json_bytes(value))
    outputs={str(p.relative_to(target)):{"bytes":p.stat().st_size,"sha256":_sha(p.read_bytes())}
             for p in sorted(target.rglob("*")) if p.is_file()}
    _new_file(target/"MANIFEST.json",canonical_json_bytes({"format":OUTPUT_FORMAT+"-manifest","files":outputs}))
    for d in sorted((p for p in target.rglob("*") if p.is_dir()),key=lambda p:len(p.parts),reverse=True):_fsync_directory(d)
    _fsync_directory(target)
    return {"status":"MATERIALIZED_OUTER_STORED_EVIDENCE_INDEX", "evidence_assessment":report["evidence_assessment"],
            "files":len(outputs),"input_manifest_sha256":report["outer_manifest_binding"]["outer_manifest_sha256"],
            "UF5":"NOT_ADJUDICATED","native_or_rights_truth_certified":False}
