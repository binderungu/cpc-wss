"""WP08 bounded offline comparisons; capture and shared join are not CPC credit.

Imports are inert. Explicit capture reads only local immutable controller bytes;
evaluation imports verified local references. No native/model/provider access.
B0 is a native-centered SOP using the same independent rules as B2; these are
not two independent algorithms. Pure B1 sees only its closed projection.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import hashlib
import importlib.util
from itertools import islice
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping

from .configuration import verify_pinned_references, PINNED_REFERENCE_MANIFEST_DIGEST
from .cpc_adapter import AdmissionContext, _dependency
from .join import CoreEntry, JoinPolicy, NativeMapping, analyze
from .ledger import SnapshotReference
from .native_capture import load_capture
from .outcomes import (Composite, ExternalRow, cpc_identifier, exposure_metadata,
                       read_analysis, selected_source, typed_value)
from .primitives import (ContractError, canonical_json_bytes, freeze_json,
                         plain_json, require_identifier)

MAX_ROWS = 10000
MAX_BYTES = 64 * 1024 * 1024
_SHARED = ('common upstream capture', 'CPC normative specification/catalogue',
           'frozen-native mapping adapter', 'WP07 downstream join')


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _bounded(items, weight=None, budget=None):
    rows = []
    budget = [MAX_BYTES] if budget is None else budget
    for item in islice(items, MAX_ROWS + 1):
        if weight is not None:
            budget[0] -= weight(item)
            if budget[0] < 0:raise ContractError('comparison stream exceeds aggregate byte bound')
        if len(rows)==MAX_ROWS:raise ContractError('comparison cohort exceeds supported bound')
        rows.append(item)
    return tuple(rows)


def _external_receipt(row):
    return {'row_ref':row.row_ref,'composite':None if row.composite is None else row.composite.to_mapping(),
        'descriptor':row.descriptor,'scalar_type':row.scalar_type,'integer_value':typed_value(row.integer_value),
        'measure_state':row.measure_state,'rubric_id':row.rubric_id,'rubric_version':row.rubric_version,
        'recipe_digest':row.recipe_digest,'lineage_ref':row.lineage_ref,'shape_valid':row.shape_valid}


@dataclass(frozen=True, slots=True)
class RawInput:
    input_ref: str
    raw: bytes = field(repr=False)

    def __post_init__(self):
        # WP06/CoreEntry input_ref domain is the WSS workflow identifier domain.
        require_identifier(self.input_ref, 'input_ref')
        if type(self.raw) is not bytes or len(self.raw) > 16777216:
            raise ContractError('raw immutable bytes within retention bound required')


def capture_native(controller, analysis_reference) -> Mapping:
    """Copy a verified local prefix and source receipts; no helper/native reads.

    Source bytes are common inputs for all full-information arms. No observations
    after this prefix or unknown/unreferenced orphan files are silently included.
    """
    basis = read_analysis(controller, analysis_reference)
    payloads, selections = {}, {}
    counts = [0, 0]
    def retain(reference):
        counts[0] += 1
        if counts[0] > 100000:
            raise ContractError('native capture reference bound exceeded')
        if reference.store_ref != controller.store._store_ref:
            raise ContractError('controller snapshot reference has foreign store')
        if reference.snapshot_ref not in payloads:
            raw = controller.store.get(reference)
            counts[1] += len(raw)
            if counts[1] > MAX_BYTES:
                raise ContractError('native capture exceeds common budget')
            payloads[reference.snapshot_ref] = raw.hex()
    retain(SnapshotReference.from_mapping(basis['reference']))
    if len(basis['events']) > 100000:
        raise ContractError('native capture event bound exceeded')
    # Only typed WP03 event fields are references. Ordinary source/value bytes
    # are never parsed to discover pointers, even if they resemble a reference.
    for event in basis['events']:
        data = event['data']
        field = {'INGESTION':'raw_snapshot','ANALYSIS':'analysis_snapshot'}.get(event['event'])
        if field is not None:retain(SnapshotReference.from_mapping(data[field]))
        if event['event']=='OBSERVATION' and data.get('capture_snapshot') is not None:
            capture = load_capture(SnapshotReference.from_mapping(data['capture_snapshot']),controller.store)
            for reference in (capture.manifest_reference,capture.raw_reference,*capture.blob_references):
                retain(reference)
    for attempt_ref, attempt in basis['view']['attempts'].items():
        if attempt['selected_followup'] is None:
            selections[attempt_ref] = {'status':'NOT_SELECTED'}
            continue
        try:
            _, follow, capture, _, _, raw = selected_source(controller, basis, attempt_ref)
        except ContractError:
            selections[attempt_ref] = {'status':'INVALID_SELECTED_SOURCE'}
        else:
            selections[attempt_ref] = {'status':'VERIFIED_LOCAL_BYTES', 'operation_ref':follow['operation_ref'],
                'value_hex':raw.hex(), 'value_digest':_digest(raw),
                'transport':capture.transport.to_mapping()}
    return freeze_json({'format':'wss-common-native-v1', 'analysis_ref':basis['document']['analysis_ref'],
        'current_head':basis['current_head'], 'view':basis['view'], 'events':basis['events'],
        'readiness_issues':list(controller.context.readiness_issues()),
        'selected_sources':selections, 'retained_local_snapshot_hex':payloads,
        'trust':'verified local supplied bytes; not native truth, permission or continuous freshness'})


@dataclass(frozen=True, slots=True)
class CommonEvidence:
    evidence_ref: str
    inputs: tuple[RawInput, ...] = field(repr=False)
    context: AdmissionContext = field(repr=False)
    native: Mapping = field(repr=False)
    exposures: Mapping[str, bytes] = field(repr=False)
    external_rows: tuple[ExternalRow, ...] = field(repr=False)
    policy: JoinPolicy
    auxiliary: Mapping[str, bytes] = field(default_factory=dict, repr=False)
    receipt: Mapping = field(init=False)
    digest: str = field(init=False)

    def __post_init__(self):
        require_identifier(self.evidence_ref, 'evidence_ref')
        if type(self.context) is not AdmissionContext or type(self.policy) is not JoinPolicy:
            raise ContractError('explicit common context and join policy required')
        budget = [MAX_BYTES]
        inputs = _bounded(self.inputs,lambda item:len(item.raw) if type(item) is RawInput else 0,budget)
        if any(type(item) is not RawInput for item in inputs) or len({r.input_ref for r in inputs}) != len(inputs):
            raise ContractError('all unique raw input refs required')
        external = _bounded((item if type(item) is ExternalRow else ExternalRow.from_mapping(item)
                             for item in self.external_rows),lambda row:len(canonical_json_bytes(_external_receipt(row))),budget)
        native = freeze_json(self.native)
        required = {'format','analysis_ref','current_head','view','events','readiness_issues',
                    'selected_sources','retained_local_snapshot_hex','trust'}
        if not isinstance(native, Mapping) or set(native) != required or native['format'] != 'wss-common-native-v1':
            raise ContractError('closed frozen native evidence required')
        if (not isinstance(native['view'], Mapping) or not isinstance(native['view'].get('attempts'), Mapping)
                or not isinstance(native['selected_sources'], Mapping) or not isinstance(native['events'], tuple)):
            raise ContractError('native evidence has invalid structural fields')
        for key in ('analysis_ref', 'current_head'):require_identifier(native[key], key)
        # Data-only inputs are supplied assertions. The explicit capture function
        # supplies locally verified bytes; construction alone cannot prove origin.
        refs = {item.input_ref for item in inputs}
        if set(self.exposures) - refs:raise ContractError('exposure outside received input scope')
        byte_maps = []
        for mapping in (self.exposures, self.auxiliary):
            copied = {}
            for key, raw in mapping.items():
                require_identifier(key, 'common byte reference')
                if type(raw) is not bytes:raise ContractError('common snapshots require immutable bytes')
                copied[key] = raw
            byte_maps.append(MappingProxyType(copied))
        exposures, auxiliary = byte_maps
        native_raw = canonical_json_bytes(native)
        external_raw = canonical_json_bytes([_external_receipt(row) for row in external])
        total = sum(len(item.raw) for item in inputs) + len(native_raw) + len(external_raw)
        total += sum(len(raw) for mapping in byte_maps for raw in mapping.values())
        total += len(canonical_json_bytes(self.context.receipt))
        if total > MAX_BYTES:raise ContractError('common evidence exceeds aggregate64MiB bound')
        policy = {key:getattr(self.policy,key) for key in ('rubric_id','rubric_version','recipe_digest')}
        receipt = {'format':'wss-common-evidence-v1', 'evidence_ref':self.evidence_ref,
            'inputs':[{'input_ref':item.input_ref,'sha256':_digest(item.raw),'bytes':len(item.raw)} for item in inputs],
            'operator_context':self.context.receipt, 'context_digest':self.context.digest,
            'native_digest':_digest(native_raw), 'external_digest':_digest(external_raw),
            'external_count':len(external), 'policy':policy,
            'exposures':{key:_digest(raw) for key,raw in exposures.items()},
            'auxiliary':{key:_digest(raw) for key,raw in auxiliary.items()}, 'aggregate_bytes':total}
        object.__setattr__(self, 'inputs', inputs)
        object.__setattr__(self, 'external_rows', external)
        object.__setattr__(self, 'native', native)
        object.__setattr__(self, 'exposures', exposures)
        object.__setattr__(self, 'auxiliary', auxiliary)
        object.__setattr__(self, 'receipt', freeze_json(receipt))
        object.__setattr__(self, 'digest', _digest(canonical_json_bytes(receipt)))


def _rules_dependency():
    """Fresh verified absolute-origin comparator; no cpc2 imports or pyc lookup."""
    refs = Path(__file__).resolve().parents[2] / 'references'
    verify_pinned_references(refs)
    origin = refs/'comparator_release/comparator/independent_rules.py'
    spec = importlib.util.spec_from_file_location('_wss_wp08_independent_rules', origin)
    module = importlib.util.module_from_spec(spec)
    exec(compile(origin.read_bytes(), str(origin), 'exec', dont_inherit=True), module.__dict__)
    if module.COMPARATOR_VERSION != '1.0.1':raise ContractError('unsupported comparator version')
    return module


def _engine_receipt(method):
    refs = Path(__file__).resolve().parents[2]/'references'
    checked = verify_pinned_references(refs)
    manifest = json.loads((refs/'REFERENCE_MANIFEST.json').read_bytes())
    prefix = 'cpc_release/' if method=='CPC_REFERENCE' else 'comparator_release/'
    return {'engine':'CPC_REFERENCE' if method=='CPC_REFERENCE' else 'independent_rules',
        'version':'2.0.2' if method=='CPC_REFERENCE' else '1.0.1',
        'contract':'2.0.1','schema':'cpc-2.0.1','manifest_sha256':checked.manifest_sha256,
        'files':{row['path']:row['copied_sha256'] for row in manifest['files'] if row['path'].startswith(prefix)}}


def frozen_mapping(native, entry: CoreEntry, exposure_raw: bytes | None) -> NativeMapping:
    """WP07 semantics on one captured prefix. Shared by all full-info arms."""
    if entry.result is None or entry.result['disposition'] != 'ADMIT':
        raise ContractError('native mapping only for actual ADMIT')
    def mapped(status, flags):
        return NativeMapping(status, tuple(flags), native['analysis_ref'], native['current_head'])
    record = entry.result['admitted_record']; view = native['view']
    attempt = view['attempts'].get(record['unit_token'])
    if attempt is None:return mapped('HOLD', ['NATIVE_OCCURRENCE_UNAVAILABLE'])
    flags = set(attempt['reason_flags']) | set(native['readiness_issues'])
    if exposure_raw is None:return mapped('PENDING', flags | {'FINAL_EXPOSURE_LINKAGE_PENDING'})
    try:exposure = exposure_metadata(exposure_raw)
    except ContractError:return mapped('HOLD', flags | {'FINAL_EXPOSURE_LINKAGE_INVALID'})
    payload = exposure['payload']
    if (exposure['record_id'] != record['exposure_record_id'] or exposure['integrity']['content_digest'] != record['exposure_digest']
            or any(exposure[name] != record[name] for name in ('unit_token','experiment_id','experiment_version'))
            or payload['artifact_version'] != record['artifact_version'] or payload['enacted_condition'] != record['attributed_condition']):
        flags.add('EXPOSURE_CORE_CONTEXT_CONFLICT')
    expected = {'WSS-U01-HINT':'hint','WSS-U01-ANSWER':'answer'}.get(attempt['logical_resource'])
    if payload['enacted_condition'] != expected:flags.add('CONDITION_RESOURCE_CONFLICT')
    invocation = view['invocations'].get(payload['invocation_id'])
    if invocation is None or invocation['attempt_ref'] != record['unit_token'] or not invocation['ever_published']:
        flags.add('PUBLICATION_LINKAGE_UNAVAILABLE')
    if attempt['selected_followup'] is not None:
        source = native['selected_sources'].get(record['unit_token'], {})
        if source.get('status') != 'VERIFIED_LOCAL_BYTES':flags.add('NATIVE_FOLLOWUP_LINKAGE_INVALID')
        else:
            ops = [event['sequence'] for event in native['events'] if event['event']=='OPERATION'
                   and event['data']['operation_ref']==source['operation_ref']]
            pubs = [event['sequence'] for event in native['events'] if event['event']=='INVOCATION_STAGE'
                    and event['data']['invocation_ref']==payload['invocation_id'] and event['data']['stage']=='PUBLISHED']
            if not ops or not pubs or min(pubs) >= ops[0]:flags.add('OUTCOME_BEFORE_EXPOSURE')
    if attempt['closed_sequence'] is None:return mapped('PENDING', flags | {'EPISODE_OPEN'})
    return mapped('HOLD', flags) if flags else mapped('ELIGIBLE', ())


def evaluate_full(common: CommonEvidence, *, method: str, cohort_ref: str, snapshot_ref: str) -> Mapping:
    """Explicit reference invocation with per-input failure accounting.

    B0/B2 call independent rules only. CPC_REFERENCE is a separate arm, using the
    same complete immutable budget. Exceptions are unresolved, not fake verdicts.
    """
    if type(common) is not CommonEvidence or method not in {'B0','B2','CPC_REFERENCE'}:
        raise ContractError('supported full-information arm and common evidence required')
    require_identifier(cohort_ref,'cohort_ref'); require_identifier(snapshot_ref,'snapshot_ref')
    entries, failures, results = [], [], []
    before = common.digest
    engine, engine_receipt = None, None
    try:
        candidate = _dependency('api') if method=='CPC_REFERENCE' else _rules_dependency()
        engine_receipt = _engine_receipt(method)
        engine = candidate
    except Exception as error:dependency_error = type(error).__name__
    for ordinal, item in enumerate(common.inputs):
        result = None
        try:
            if engine is None:raise ContractError('dependency unavailable: '+dependency_error)
            profile, keys, now = common.context.arguments() # Fresh isolated copies for each invocation.
            # Comparator1.0.1 accepts UTF8 text secrets; CPC also accepts bytes.
            # This lossless transport adapter preserves the exact HMAC key bytes.
            # Non-UTF8 byte keys cannot be represented: unresolved, never replaced.
            if method!='CPC_REFERENCE' and isinstance(keys, dict):
                keys = {key:value.decode('utf-8') if type(value) is bytes else value for key,value in keys.items()}
            pristine = AdmissionContext(profile,keys,now).digest
            result = engine.validate_raw(item.raw, profile, keys, now, input_ref=item.input_ref)
            if AdmissionContext(profile,keys,now).digest != pristine:raise ContractError('reference mutated operator inputs')
            if not isinstance(result, Mapping) or not isinstance(result.get('diagnostics'), (list,tuple)):
                raise ContractError('reference result shape invalid')
            if any(not isinstance(row, Mapping) for row in result['diagnostics']):raise ContractError('diagnostic row invalid')
            if result.get('input_sha256') != _digest(item.raw):raise ContractError('reference raw digest mismatch')
            entry = CoreEntry(method+':receipt:'+str(ordinal), item.input_ref, result)
        except Exception as error:
            # Do not emit exception text, DSN, key material, or arbitrary engine return.
            failures.append({'input_ref':item.input_ref,'phase':'dependency' if engine is None else 'evaluation_or_shape',
                             'exception_type':type(error).__name__, 'result_status':'UNRESOLVED'})
            entry = CoreEntry(method+':receipt:'+str(ordinal), item.input_ref, None)
        entries.append(entry)
        results.append({'input_ref':item.input_ref,'raw_digest':_digest(item.raw),'result':entry.result})
    mappings = {}
    for entry in entries:
        if entry.result is not None and entry.result['disposition']=='ADMIT':
            try:mappings[entry.receipt_ref] = frozen_mapping(common.native, entry, common.exposures.get(entry.input_ref))
            except Exception as error:
                failures.append({'input_ref':entry.input_ref,'phase':'native_mapping',
                                 'exception_type':type(error).__name__,'result_status':'CORE_RESULT_RETAINED_MAPPING_PENDING'})
                mappings[entry.receipt_ref] = NativeMapping('PENDING', ('NATIVE_MAPPING_EVALUATION_UNRESOLVED',))
    joined = analyze(entries, common.external_rows, mappings, common.policy,
                     cohort_ref=cohort_ref,snapshot_ref=snapshot_ref)
    if common.digest != before:raise ContractError('common evidence changed')
    return freeze_json({'format':'wss-full-information-arm-v1','method':method,
        'common_evidence_digest':common.digest,'access_receipt':common.receipt,
        'engine_receipt':engine_receipt,
        'shared_dependencies':list(_SHARED), 'B0_B2_rule_engine_shared':True,
        'key_transport':'CPC native registry; B0/B2 exact UTF8 byte-to-text roundtrip only, else unresolved',
        'status':'INCOMPLETE_EVALUATION' if failures else 'EVALUATED',
        'results':results,'failures':failures,'join':joined,
        'native_sop_rows':[{'attempt_ref':key,'selected_source':{k:v for k,v in common.native['selected_sources'].get(key,{}).items()
                            if k not in {'value_hex','transport'}},
                            'native_reason_flags':row.get('reason_flags')} for key,row in common.native['view']['attempts'].items()]
                          if method=='B0' else [],
        'Y_next':'NOT_MEASURED / NOT_VALIDATED_HERE', 'UF5':'NOT_ADJUDICATED'})


@dataclass(frozen=True, slots=True)
class AblationRow:
    """Only the permitted B1 slice. No full input, native, profile, or join handle."""
    pair_key: str | None
    reported_label: str | None
    scalar_descriptor: Mapping = field(repr=False)

    def __post_init__(self):
        if self.pair_key is not None:require_identifier(self.pair_key,'opaque pair key')
        if self.reported_label is not None:cpc_identifier(self.reported_label,'reported label')
        descriptor = freeze_json(self.scalar_descriptor)
        shapes = {'null':{'type'}, 'non_scalar':{'type'}, 'unavailable':{'type'},
                  'bool':{'type','value'},'str':{'type','value'},'int':{'type','decimal'},
                  'float':{'type','hex'},'str-surrogatepass':{'type','hex'}}
        if (not isinstance(descriptor, Mapping) or type(descriptor.get('type')) is not str
                or set(descriptor) != shapes.get(descriptor['type']) or len(canonical_json_bytes(descriptor))>1048576):
            raise ContractError('bounded scalar descriptor required')
        for key,value in descriptor.items():
            if key=='value' and type(value) is not (bool if descriptor['type']=='bool' else str):
                raise ContractError('scalar descriptor type mismatch')
            if key in {'hex','decimal'} and type(value) is not str:raise ContractError('scalar text required')
        kind = descriptor['type']
        if kind=='int' and not re.fullmatch(r'0|-?[1-9][0-9]*',descriptor['decimal']):
            raise ContractError('canonical integer descriptor required')
        if kind=='float':
            try:valid = float.fromhex(descriptor['hex']).hex()==descriptor['hex']
            except ValueError:valid = False
            if not valid:raise ContractError('canonical float descriptor required')
        if kind=='str-surrogatepass':
            try:valid = bytes.fromhex(descriptor['hex']).hex()==descriptor['hex']
            except ValueError:valid = False
            if not valid:raise ContractError('canonical surrogate-byte hex required')
        object.__setattr__(self,'scalar_descriptor',descriptor)


def project_b1(common: CommonEvidence) -> tuple[tuple[AblationRow,...],tuple[AblationRow,...]]:
    """Explicit lossy projection from ALL raw inputs, never from ADMIT filter.

    Pair keys are opaque digests of the reported seven-field key, not verified
    identities. Only key equality/cardinality/label/scalar is exposed to B1.
    """
    def pair(composite):
        return None if composite is None else 'pair:'+hashlib.sha256(canonical_json_bytes(composite.to_mapping())).hexdigest()
    core = []
    for item in common.inputs:
        composite, label = None, None
        try:
            def unique(pairs):
                result = {}
                for key,value in pairs:
                    if key in result:raise ValueError('duplicate')
                    result[key]=value
                return result
            chain = json.loads(item.raw, object_pairs_hook=unique)
            exposure = [row for row in chain['records'] if row['record_type']=='exposure']
            outcome = [row for row in chain['records'] if row['record_type']=='outcome']
            if len(exposure)==len(outcome)==1:
                ep, op = exposure[0], outcome[0]
                composite = Composite.interpret({**{k:ep.get(k) for k in ('experiment_id','experiment_version','unit_token')},
                    'exposure_record_id':ep.get('record_id'),'exposure_digest':ep.get('integrity',{}).get('content_digest'),
                    'outcome_key':op['payload'].get('outcome_key'),'purpose':op['payload'].get('purpose')})
                label = cpc_identifier(op['payload']['attributed_condition'],'reported label')
        except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,RecursionError):pass
        core.append(AblationRow(pair(composite),label,typed_value(None)))
    def scalar(row):
        if row.scalar_type=='int':return typed_value(row.integer_value)
        for item in row.descriptor.get('items', ()):
            if item.get('key') == {'type':'str','value':'value'}:
                desc = item['value']
                return {'type':'non_scalar'} if desc.get('type') in {'array','object'} else desc
        return {'type':'unavailable'}
    external = tuple(AblationRow(pair(row.composite),None,scalar(row)) for row in common.external_rows)
    return tuple(core), external


def evaluate_b1(core_rows, external_rows, *, cohort_ref: str, snapshot_ref: str) -> Mapping:
    """Pure ablation; observing a singleton never establishes attribution."""
    require_identifier(cohort_ref,'cohort_ref');require_identifier(snapshot_ref,'snapshot_ref')
    def weight(row):
        return len(canonical_json_bytes({'key':row.pair_key,'label':row.reported_label,'scalar':row.scalar_descriptor})) if type(row) is AblationRow else 0
    budget = [MAX_BYTES]
    core, external = _bounded(core_rows,weight,budget), _bounded(external_rows,weight,budget)
    if any(type(row) is not AblationRow for row in (*core,*external)):
        raise ContractError('B1 accepts only closed AblationRow inputs')
    cc, ec = Counter(row.pair_key for row in core if row.pair_key is not None), Counter(row.pair_key for row in external if row.pair_key is not None)
    ledger = []
    for ordinal,row in enumerate(core):
        observed = 'KEY_UNINTERPRETABLE' if row.pair_key is None else 'CORE_KEY_AMBIGUOUS' if cc[row.pair_key]!=1 else 'EXTERNAL_KEY_AMBIGUOUS' if ec[row.pair_key]>1 else 'EXTERNAL_MISSING' if ec[row.pair_key]==0 else 'REPORTED_SINGLETON'
        ledger.append({'ordinal':ordinal,'pair_key':row.pair_key,'reported_label':row.reported_label,
            'cardinality_observation':observed,'attribution':'UNKNOWN','decision':'ABSTAIN',
            'reason':'NATIVE_AUTHORITY_AND_INPUT_USE_NOT_AVAILABLE_IN_ABLATION'})
    return freeze_json({'format':'wss-b1-ablation-v1','cohort_ref':cohort_ref,'snapshot_ref':snapshot_ref,
        'received_core':len(core),'received_external':len(external),'ledger':ledger,
        'external_ledger':[{'ordinal':n,'pair_key':row.pair_key,'scalar_descriptor':row.scalar_descriptor} for n,row in enumerate(external)],
        'attributed_joined':0,'abstained':len(core),'status':'RESTRICTED_ABLATION_NOT_A_VALIDATED_JOIN',
        'information_budget':['opaque pair key','reported label','scalar descriptor','received cardinality']})


def compare_full(reference: Mapping, alternative: Mapping) -> Mapping:
    """Disagreements demand diagnosis, never reward one implementation."""
    expected = {'format','method','common_evidence_digest','access_receipt','engine_receipt','shared_dependencies',
                'B0_B2_rule_engine_shared','key_transport','status','results','failures','join','native_sop_rows','Y_next','UF5'}
    for arm in (reference,alternative):
        if (set(arm)!=expected or arm['format']!='wss-full-information-arm-v1'
                or arm['method'] not in {'CPC_REFERENCE','B0','B2'} or arm['status'] not in {'EVALUATED','INCOMPLETE_EVALUATION'}):
            raise ContractError('supported closed full-information arm required')
        pin = arm['engine_receipt']
        if pin is None:
            if arm['status']!='INCOMPLETE_EVALUATION' or any(row['result'] is not None for row in arm['results']):
                raise ContractError('missing executed engine pin')
        else:
            cpc = arm['method']=='CPC_REFERENCE'
            if (set(pin)!={'engine','version','contract','schema','manifest_sha256','files'}
                    or pin['manifest_sha256']!=PINNED_REFERENCE_MANIFEST_DIGEST
                    or pin['engine']!=('CPC_REFERENCE' if cpc else 'independent_rules')
                    or pin['version']!=('2.0.2' if cpc else '1.0.1') or pin['contract']!='2.0.1' or pin['schema']!='cpc-2.0.1'):
                raise ContractError('engine receipt does not match expected pin')
            if not cpc and dict(pin['files'])!={
                    'comparator_release/comparator/independent_rules.py':'sha256:3db0709ed4384c371a15df812791cc3a3ba98a94ee6f8b8164d842cc7e68504a',
                    'comparator_release/implementation/spec/FIELD_REQUIREMENTS.json':'sha256:33b936510b79147e946729c2099bc264a83f9597ec3b91635910a4b8349fb8b6'}:
                raise ContractError('comparator source/catalogue pin mismatch')
            if cpc and (pin['files'].get('cpc_release/implementation/src/cpc2/api.py')!='sha256:3e2f5e1c12886698427e86a5a0f21e6071cc9911d963e370dd18a09425348653'
                        or pin['files'].get('cpc_release/implementation/src/cpc2/validator.py')!='sha256:4a4791eca1294c4bc4fb284bdd89c3f4318f0ba913d3ccd1b312756078f6ce0c'):
                raise ContractError('CPC source pin mismatch')
    if reference['common_evidence_digest'] != alternative['common_evidence_digest']:
        raise ContractError('unequal common evidence budgets')
    if canonical_json_bytes(reference['access_receipt']) != canonical_json_bytes(alternative['access_receipt']):
        raise ContractError('unequal common access receipts')
    refs = {row['input_ref']:row for row in reference['results']}
    alts = {row['input_ref']:row for row in alternative['results']}
    if len(refs)!=len(reference['results']) or len(alts)!=len(alternative['results']) or set(refs)!=set(alts):
        raise ContractError('comparison received input scopes differ')
    if any(refs[key]['raw_digest']!=alts[key]['raw_digest'] for key in refs):
        raise ContractError('comparison raw input digests differ')
    def different(field):
        return [key for key in refs if canonical_json_bytes(None if refs[key]['result'] is None else refs[key]['result'][field])
                != canonical_json_bytes(None if alts[key]['result'] is None else alts[key]['result'][field])]
    verdicts, exports, diagnostics = (different(field) for field in ('disposition','admitted_record','diagnostics'))
    def joins(arm):
        return {row['input_ref']:{key:value for key,value in row.items() if key!='receipt_ref'} for row in arm['join']['core_ledger']}
    rj, aj = joins(reference), joins(alternative)
    join_differences = [key for key in refs if canonical_json_bytes(rj[key])!=canonical_json_bytes(aj[key])]
    counts_differ = canonical_json_bytes(reference['join']['counts'])!=canonical_json_bytes(alternative['join']['counts'])
    incomplete = any(arm['status']=='INCOMPLETE_EVALUATION' or any(row['result'] is None for row in arm['results'])
                     for arm in (reference,alternative))
    state = 'INCOMPLETE_EVALUATION' if incomplete else 'MISMATCH_REQUIRES_DIAGNOSIS' if verdicts or exports or join_differences or counts_differ else 'MATCH'
    return freeze_json({'status':state,'common_evidence_digest':reference['common_evidence_digest'],
        'disposition_differences':verdicts,'normalized_export_differences':exports,
        'join_differences':join_differences,'denominator_difference':counts_differ,
        'diagnostic_wording_differences':diagnostics,
        'interpretation':'Differences require bug/spec/access diagnosis; equality is allowed; no superiority or UF5 inference'})


def run_comparison(common: CommonEvidence, *, cohort_ref: str, snapshot_ref: str) -> Mapping:
    arms = {method:evaluate_full(common,method=method,cohort_ref=cohort_ref,snapshot_ref=snapshot_ref)
            for method in ('CPC_REFERENCE','B0','B2')}
    core, external = project_b1(common)
    b1 = evaluate_b1(core, external, cohort_ref=cohort_ref,snapshot_ref=snapshot_ref)
    return freeze_json({'format':'wss-comparison-v1','arms':arms,'B1':b1,
        'comparisons':{method:compare_full(arms['CPC_REFERENCE'],arms[method]) for method in ('B0','B2')},
        'scientific_JLA_sufficiency':'INSUFFICIENT_EVIDENCE_UNCHANGED','UF1_UF6':'NOT_ADJUDICATED',
        'Y_next':'NOT_MEASURED / NOT_VALIDATED_HERE'})
