"""One-shot outer coordinator: external acquisition, guarded offline processing.

Explicit POSIX entry point only. No imports create authority or native actions.
Synthetic qualification and bounded native acquisition have distinct manifests.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import multiprocessing
import os
from pathlib import Path
import stat
import time

from .primitives import ContractError, canonical_json_bytes, plain_json
from .ledger import _real_directory
from .worked_runner import RunnerConfig, run_offline, verify_worked_output
from .operator_ports import SuppliedOperatorPorts
from .native_exchange import create_exchange, FileOperationPort, read_request, publish_response
from .native_acquisition import BoundedNativeAcquirer
from .native_http import MoodleFormClient
from .native_process import NativeHelperProcess
from .counterparts import materialize_counterparts

MODES = {'SYNTHETIC_OFFLINE_QUALIFICATION', 'BOUNDED_NATIVE_ACQUISITION'}


def _sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _save(path, value):
    raw = canonical_json_bytes(plain_json(value))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    parent = os.open(Path(path).parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def supplied_bindings(config, operator, *, source_manifest_digest, design_digest,
                      preflight_digest, authority_digest):
    """Fingerprint supplied objects; not a human approval/source-truth oracle.

    Private operator attributes are version-pinned integration seams. All actual
    key bytes are reduced to one-way fingerprints before public serialization.
    """
    if type(config) is not RunnerConfig or type(operator) is not SuppliedOperatorPorts:
        raise ContractError('typed config/operator required')
    policy = operator._policy
    return {'run_ref': config.scope.run_ref,
        'runner_config_digest': _sha(canonical_json_bytes(config.to_mapping())),
        'controller_context_digest': _sha(canonical_json_bytes(config.context.to_mapping())),
        'source_epoch_ref': config.context.source.source_epoch_ref,
        'source_manifest_digest': source_manifest_digest, 'design_digest': design_digest,
        'preflight_digest': preflight_digest, 'authority_digest': authority_digest,
        'profile_digest': _sha(policy.profile_raw), 'bundle_map_digest': _sha(policy.bundle_map_raw),
        'catalog_digest': operator._catalog.digest, 'recipe_digest': operator._recipe.digest,
        'prompt_digests': {k:_sha(v) for k,v in operator._prompts.items()},
        'generation_digests': {k:_sha(v) for k,v in operator._generations.items()},
        'key_fingerprints': {k:_sha(v) for k,v in policy.key_registry.items()},
        'content_review_ref': operator._review, 'internal_rights_ref': operator._rights,
        'consent_declaration_digest': _sha(canonical_json_bytes(operator._consent)),
        'eligibility_declaration': operator._eligibility}


def validate_grant(grant, bindings, *, mode, authority, preflight):
    if mode not in MODES or grant.get('format') != 'wss-worked-execution-grant-v1':
        raise ContractError('exact execution mode/grant format required')
    if grant.get('mode') != mode or grant.get('bindings') != bindings:
        raise ContractError('grant exact version/input binding differs')
    if grant.get('bindings_digest') != _sha(canonical_json_bytes(bindings)):
        raise ContractError('grant bindings digest differs')
    expected = {'max_TASK_finalizations':3, 'max_FOLLOWUP_finalizations':3,
                'max_protocol_helper_calls':18, 'max_publication_attempts':4}
    if any(type(grant.get(k)) is not int or grant[k] != v for k,v in expected.items()):
        raise ContractError('grant exact candidate budget differs')
    try:
        start, end = (datetime.fromisoformat(grant[k]) for k in ('valid_from_UTC','expires_UTC'))
    except (ValueError, TypeError, KeyError):
        raise ContractError('grant validity required')
    now = datetime.now(timezone.utc)
    if start.tzinfo is None or end.tzinfo is None or not start <= now < end:
        raise ContractError('grant current window required')
    if mode == 'BOUNDED_NATIVE_ACQUISITION':
        if (grant.get('native_execution_authorized') is not True
                or authority.get('origin') != 'DIRECT_USER_MESSAGE'
                or not all(authority.get(k) is True for k in
                    ('material_internal_use_approved','sole_operator_confirmed','native_scope_approved'))
                or grant.get('owner_authorization_ref') != authority.get('record_ref')
                or grant.get('sole_writer_ref') != authority.get('sole_writer_ref')
                or preflight.get('status') != 'CURRENT_PREFLIGHT_VERIFIED'
                or preflight.get('controller_context_digest') != bindings['controller_context_digest']):
            raise ContractError('current human facts/preflight not established')
    elif grant.get('native_execution_authorized') is not False:
        raise ContractError('qualification must not claim native authorization')


def _child(root, config, ports):
    try:
        with (root/'private/child.stdout.raw').open('xb') as out, (root/'private/child.stderr.raw').open('xb') as err:
            os.dup2(out.fileno(), 1)
            os.dup2(err.fileno(), 2)
            result = run_offline(root/'runner', config, ports)
            _save(root/'child_result.json', result.to_mapping())
            verify_worked_output(root/'runner')
            if result.status != 'COMPLETED':
                raise ContractError('child result incomplete')
    except BaseException as exc:
        _save(root/'child_failure.json', {'exception_type':type(exc).__name__, 'no_retry':True})
        raise SystemExit(1)


def _inventory(root, *, exclude=('private',)):
    files = {}
    total = 0
    for p in sorted(root.rglob('*')):
        rel = p.relative_to(root)
        if any(part in exclude for part in rel.parts):
            continue
        info = p.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ContractError('outer inventory nonregular/multilink object')
        total += info.st_size
        if total > 128*1024*1024 or len(files) >= 5000:
            raise ContractError('outer public evidence budget exceeded')
        files[str(rel)] = {'sha256':_sha(p.read_bytes()), 'bytes':info.st_size}
    return files


def _verify_source_manifest(path):
    base = path.parent.resolve()
    declared = set()
    for line in path.read_text().splitlines():
        digest, rel = line.split(None, 1)
        if rel in declared:
            raise ContractError('duplicate source manifest entry')
        declared.add(rel)
        leaf = base/rel
        if (Path(rel).is_absolute() or '..' in Path(rel).parts
                or leaf.is_symlink() or not leaf.is_file()
                or hashlib.sha256(leaf.read_bytes()).hexdigest() != digest):
            raise ContractError('sealed source payload changed')
    actual = {str(p.relative_to(base)) for p in base.rglob('*')
              if p.is_file() and p != path}
    if actual != declared:
        raise ContractError('source manifest file coverage differs')


def run_campaign(new_root, config, *, mode, operator_factory, acquirer_factory,
                 grant, authority, preflight, design_bytes, source_manifest_path,
                 current_gate, timeout_seconds=300):
    """Compose one exclusive run, not preflight or permission creation.

    Factories are explicit trusted application code, never dynamic module names.
    Native acquirer factory must supply the scoped actual HTTP/helper adapters,
    perform ordinary actor login and preserve its receipt after the bound gate.
    This API refuses synthetic factories in native mode. Human records/preflight
    are supplied evidence, not authenticated by this software.
    """
    if mode not in MODES or type(config) is not RunnerConfig or not callable(current_gate):
        raise ContractError('explicit typed mode/config/current gate required')
    if (type(timeout_seconds) not in (int,float) or not 0 < timeout_seconds <= 600
            or len(config.episodes) != 3
            or [e.publications for e in config.episodes] != [1,1,2]
            or any(e.outcome_owner_ordinal != 1 for e in config.episodes)
            or (config.max_operations,config.max_observations,config.max_publications) != (6,18,4)):
        raise ContractError('exact bounded three-episode plan required')
    root = _real_directory(new_root, exists=False)
    manifest = Path(source_manifest_path)
    if manifest.is_symlink() or not manifest.is_file():
        raise ContractError('sealed source manifest required')
    if mode == 'BOUNDED_NATIVE_ACQUISITION' and manifest.resolve() != Path(__file__).resolve().parents[2]/'SOURCE_MANIFEST.sha256':
        raise ContractError('native mode requires exact package source manifest')
    source_digest = _sha(manifest.read_bytes())
    _verify_source_manifest(manifest)
    root.mkdir(mode=0o700)
    for name in ('freeze','private','native_events'):
        (root/name).mkdir(mode=0o700)
    create_exchange(root/'exchange', config.scope.run_ref,
                    max_operations=6,max_observations=18,timeout_seconds=60)
    operation = FileOperationPort(root/'exchange')
    operator = operator_factory(operation)
    if type(operator) is not SuppliedOperatorPorts or operator.ports.operation is not operation:
        raise ContractError('exact guarded exchange operator required')
    bindings = supplied_bindings(config, operator, source_manifest_digest=source_digest,
        design_digest=_sha(design_bytes), preflight_digest=_sha(canonical_json_bytes(preflight)),
        authority_digest=_sha(canonical_json_bytes(authority)))
    validate_grant(grant, bindings, mode=mode, authority=authority, preflight=preflight)
    for name,value in [('EXECUTION_GRANT',grant),('AUTHORITY',authority),('PREFLIGHT',preflight),
                        ('BINDINGS',bindings),('RUNNER_CONFIG',config.to_mapping())]:
        _save(root/'freeze'/(name+'.json'), value)
    _save(root/'STARTED.json', {'mode':mode,'native_truth_independently_attested':False,
                              'scientific_or_release_approval':False,'one_shot':True})
    sequence = 0
    def record(kind, data):
        nonlocal sequence
        sequence += 1
        _save(root/'native_events'/(str(sequence).zfill(5)+'_'+kind+'.json'), {
            'kind':kind,'UTC':datetime.now(timezone.utc).isoformat(),
            'monotonic_ns':time.monotonic_ns(),'data':data})
    def gate():
        validate_grant(grant, bindings, mode=mode, authority=authority, preflight=preflight)
        if (root/'STOP').exists() or _sha(manifest.read_bytes()) != source_digest:
            raise ContractError('external stop or source manifest changed')
        _verify_source_manifest(manifest)
        current_gate()
    gate()
    acquirer = acquirer_factory(gate, record)
    if mode == 'BOUNDED_NATIVE_ACQUISITION':
        if (type(acquirer) is not BoundedNativeAcquirer
                or type(acquirer.client) is not MoodleFormClient
                or type(acquirer.helper_read) is not NativeHelperProcess
                or acquirer.gate is not gate or acquirer.helper_read.gate is not gate
                or not callable(acquirer.pre_submit_gate)
                or acquirer.client.authenticated is not True
                or acquirer.order != tuple((e.episode_ref,k) for e in config.episodes for k in ('TASK','FOLLOWUP'))):
            raise ContractError('actual scoped native adapter integration required')
    elif type(acquirer) is BoundedNativeAcquirer:
        raise ContractError('qualification requires fake external acquirer')
    process = multiprocessing.get_context('fork').Process(target=_child,
        args=(root,config,operator.ports), name='cpc-wss-guarded-child')
    deadline = time.monotonic() + timeout_seconds
    ordinal, failure, started = 1, None, False
    try:
        process.start()
        started = True
        while process.is_alive():
            gate()
            if time.monotonic() > deadline:
                raise ContractError('outer run deadline exceeded')
            request = None if ordinal > 6 else read_request(root/'exchange', ordinal)
            if request is None:
                time.sleep(.01)
                continue
            op = request['operation']
            if _sha(canonical_json_bytes(op['context'])) != bindings['controller_context_digest']:
                raise ContractError('request exact grant context differs')
            result, evidence = acquirer.acquire(request)
            gate()
            publish_response(root/'exchange',ordinal,result,process_evidence=evidence)
            ordinal += 1
        process.join()
        if process.exitcode != 0:
            raise ContractError('guarded child failed; no retry')
        gate()
        if ordinal != 7:
            raise ContractError('six prospective operations not reached')
        verify_worked_output(root/'runner')
        materialize_counterparts(root/'runner',root/'counterparts')
    except Exception as exc:
        failure = {'exception_type':type(exc).__name__,'no_retry':True,
                   'next_request_ordinal':ordinal}
    finally:
        if started and process.is_alive():
            process.terminate()
            process.join(timeout=2)
            if process.is_alive():
                process.kill()
                process.join(timeout=2)
        _save(root/'CHILD_EXIT.json',{'exit_code':process.exitcode,'forced_stop':failure is not None})
    status = 'FAILED' if failure else 'COMPLETED'
    if failure:
        _save(root/'OUTER_FAILURE.json',failure)
    record('PARENT_TERMINAL',{'status':status,'child_exit_code':process.exitcode,
                             'operation_responses_published':ordinal-1})
    outer = {'format':'wss-outer-acquisition-inputs-v1','mode':mode,'files':_inventory(root),
        'runner_root':'runner','counterpart_root':'counterparts',
        'grant_ref':'freeze/EXECUTION_GRANT.json','preflight_ref':'freeze/PREFLIGHT.json',
        'event_root':'native_events','process_root':'native_reads',
        'child_exit_code':process.exitcode,'parent_status':status}
    _save(root/'OUTER_EVIDENCE_MANIFEST.json',outer)
    if not failure:
        try:
            from .outer_evidence import materialize_outer_handoff
            materialize_outer_handoff(root,root/'outer_handoff')
        except Exception as exc:
            status = 'FAILED'
            failure = {'exception_type':type(exc).__name__,
                       'phase':'OUTER_HANDOFF_DELIVERY','no_retry':True}
            _save(root/'OUTER_DELIVERY_FAILURE.json',failure)
            record('PARENT_POSTPROCESS_FAILURE',failure)
    _save(root/'CAMPAIGN_RESULT.json',{'status':status,'mode':mode,
        'child_exit_code':process.exitcode,'no_retry':True,
        'UF1_UF6':'NOT_ADJUDICATED','scientific_or_submission_approval':False})
    _save(root/'CAMPAIGN_MANIFEST.json',{'format':'wss-campaign-manifest-v1','files':_inventory(root)})
    return {'status':status,'child_exit_code':process.exitcode,'mode':mode}
