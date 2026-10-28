"""WP09 offline handoff: pure reconstruction plus explicit local IO boundaries.

No native/helper/core/comparator/producer execution. Returned data is supplied
evidence, never authority, scientific utility, anonymization or release approval.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Mapping

from .baselines import CommonEvidence, compare_full, frozen_mapping, project_b1, evaluate_b1
from .episode import project_events
from .join import CoreEntry, NativeMapping, analyze
from .ledger import (SnapshotStore, SnapshotReference, LedgerError, _real_directory, _new_file,
                     _read_file, _fsync_directory)
from .outcomes import Composite, OutcomeRecipe, exposure_metadata, external_from_outcome
from .native_transport import NativeReadTransport
from .native_capture import CAPTURE_FORMAT
from .producer_references import ProducerReferenceIndex
from .primitives import (ContractError, canonical_json_bytes, decode_json_object,
                         freeze_json, plain_json, require_identifier)

MAX_BYTES = 64*1024*1024
MAX_FILE = 16*1024*1024
MAX_NODES = 10000
_ROLES = {'CONTROLLER','PRODUCER','OUTCOME','ADAPTER'}
_GRAINS = ('opportunities','operations','ingestions','occurrences','attempts',
           'invocations','publications','followups','analyses')
_NEGATIVES = tuple({'input_ref':ref,'archived_core':'ADMIT','archived_primary_join':'JOINED',
    'archived_physical_binding':'MISMATCH','actual_registry_match':False,'reported_registry_match':True,
    'actual_prompt_differs':True,'actual_generation_differs':True,'mitigated':False}
    for ref in ('D3-00014','D3-00029','D3-00044','D3-00059'))
_BOUNDARIES = {'evidence':'SYNTHETIC_OFFLINE_MECHANICAL_QA','native_checkpoint':'NOT_RUN',
    'UF1_UF6':'NOT_ADJUDICATED','Y_next':'NOT_MEASURED / NOT_VALIDATED_HERE',
    'JLA':'INSUFFICIENT_EVIDENCE_UNCHANGED','release':'NOT_AUTHORIZED',
    'G0_count':None,'G0_balance':None,'G0_reset':False}


def _sha(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()
def _same(a,b):return canonical_json_bytes(a)==canonical_json_bytes(b)
def _check(condition, message):
    if not condition:raise ContractError(message)


@dataclass(frozen=True, slots=True)
class StoreInventory:
    """Typed point-in-time receipt. Construction alone is a supplied assertion."""
    role: str
    store_ref: str
    files: tuple[Mapping, ...]
    references: tuple[Mapping, ...]
    complete: bool

    def __post_init__(self):
        _check(self.role in _ROLES and type(self.complete) is bool,'inventory role/status invalid')
        require_identifier(self.store_ref,'store_ref')
        _check(type(self.files) is tuple and len(self.files)<=MAX_NODES,'inventory bound')
        _check(type(self.references) is tuple and len(self.references)<=MAX_NODES,'reference bound')
        for row in self.files:
            _check(set(row)=={'name','kind','classification','sha256','byte_length'},'inventory row shape')
            _check(type(row['name']) is str and re.fullmatch(r'[0-9a-f]{64}\.bin',row['name']), 'snapshot filename invalid')
            _check(row['kind'] in {'REGULAR','SYMLINK','FIFO','OTHER'},'inventory kind invalid')
            _check(row['classification'] in {'REFERENCED','ORPHAN','UNREADABLE_OR_CHANGED','NONREGULAR'},'inventory classification invalid')
            _check((row['kind']=='REGULAR' and row['classification']!='NONREGULAR') or
                   (row['kind']!='REGULAR' and row['classification']=='NONREGULAR' and row['sha256'] is None and row['byte_length'] is None),
                   'inventory kind/classification contradicts')
            if row['kind']=='REGULAR' and row['classification'] in {'REFERENCED','ORPHAN'}:
                _check(type(row['sha256']) is str and re.fullmatch(r'sha256:[0-9a-f]{64}',row['sha256'])
                       and type(row['byte_length']) is int and 0<=row['byte_length']<=MAX_FILE,'inventory digest/size invalid')
        _check(len({row['name'] for row in self.files})==len(self.files),'duplicate inventory file')
        seen=set()
        for row in self.references:
            _check(set(row)=={'reference','status'},'inventory reference shape')
            _check(row['status'] in {'MATCH','MISSING_OR_INVALID'},'inventory reference status')
            ref=SnapshotReference.from_mapping(row['reference'])
            _check(ref.store_ref==self.store_ref,'inventory reference scope mismatch')
            _check(ref.snapshot_ref not in seen,'duplicate inventory reference');seen.add(ref.snapshot_ref)
            if row['status']=='MATCH':
                name=hashlib.sha256(ref.snapshot_ref.encode()).hexdigest()+'.bin'
                files=[f for f in self.files if f['name']==name]
                _check(len(files)==1 and files[0]['kind']=='REGULAR' and files[0]['classification']=='REFERENCED' and files[0]['sha256']==ref.sha256
                       and files[0]['byte_length']==ref.byte_length,'matched reference lacks matching file')
        if self.complete:
            _check(all(row['status']=='MATCH' for row in self.references)
                and all(row['kind']=='REGULAR' and row['classification']!='UNREADABLE_OR_CHANGED' for row in self.files),
                'inventory cannot declare complete with failed/nonregular rows')
        object.__setattr__(self,'files',tuple(freeze_json(row) for row in self.files))
        object.__setattr__(self,'references',tuple(freeze_json(row) for row in self.references))

    def to_mapping(self):
        return {'role':self.role,'store_ref':self.store_ref,'files':self.files,
                'references':self.references,'complete':self.complete}


def capture_inventory(store: SnapshotStore, role: str, references=()) -> StoreInventory:
    """Explicit local lstat/read-only inventory; no recursive/payload traversal.

    Only the declared flat SnapshotStore is visited. Nonregular payloads are
    listed without opening them. Errors retain failure markers, not private text.
    """
    _check(type(store) is SnapshotStore and role in _ROLES,'declared typed store required')
    store._check_metadata()
    refs, known, ref_total = [], set(), 0
    for index,ref in enumerate(references):
        _check(index<MAX_NODES and type(ref) is SnapshotReference and ref.store_ref==store._store_ref,'reference scope/bound')
        known.add(store._path(ref.snapshot_ref).name)
        try:
            ref_total+=ref.byte_length
            _check(ref_total<=MAX_BYTES,'reference read byte bound')
            store.get(ref);status='MATCH'
        except (OSError,ValueError,LedgerError):status='MISSING_OR_INVALID'
        refs.append({'reference':ref.to_mapping(),'status':status})
    files, total = [], 0
    for path in sorted(store._directory.iterdir()):
        if path.name=='snapshot-store.meta.json':continue
        _check(len(files)<MAX_NODES and re.fullmatch(r'[0-9a-f]{64}\.bin',path.name),'unsupported store entry/bound')
        mode=path.lstat().st_mode
        kind='REGULAR' if stat.S_ISREG(mode) else 'SYMLINK' if stat.S_ISLNK(mode) else 'FIFO' if stat.S_ISFIFO(mode) else 'OTHER'
        digest, size = None, None
        classification='NONREGULAR'
        if kind=='REGULAR':
            try:
                size=path.lstat().st_size;total+=size
                _check(total<=MAX_BYTES,'inventory aggregate byte bound')
                raw=_read_file(path,MAX_FILE)
                digest,size=_sha(raw),len(raw)
                classification='REFERENCED' if path.name in known else 'ORPHAN'
            except (OSError,ValueError,LedgerError):classification='UNREADABLE_OR_CHANGED'
        files.append({'name':path.name,'kind':kind,'classification':classification,'sha256':digest,'byte_length':size})
    complete=all(row['status']=='MATCH' for row in refs) and all(row['kind']=='REGULAR' and row['classification']!='UNREADABLE_OR_CHANGED' for row in files)
    return StoreInventory(role,store._store_ref,tuple(files),tuple(refs),complete)


def capture_producer_inventory(producer_root,*,invocation_ref,call_ref) -> StoreInventory:
    """Explicit local typed-index read, never a scan of snapshot payload shapes.

    Old stores with no index fail closed; no reference reconstruction/migration.
    Unindexed files in a new store remain ORPHAN under ordinary inventory rules.
    """
    index=ProducerReferenceIndex.open_readonly(producer_root,invocation_ref=invocation_ref,call_ref=call_ref)
    inventory=capture_inventory(index.store,'PRODUCER',index.references())
    if any(row['classification']=='ORPHAN' for row in inventory.files):
        return StoreInventory(inventory.role,inventory.store_ref,inventory.files,inventory.references,False)
    return inventory


def _verified_comparison(common,comparison):
    _check(set(comparison)=={'format','arms','B1','comparisons','scientific_JLA_sufficiency','UF1_UF6','Y_next'}
           and comparison['format']=='wss-comparison-v1','comparison format invalid')
    arms=comparison['arms'];_check(set(arms)=={'CPC_REFERENCE','B0','B2'},'comparison arm scope')
    _check(comparison['scientific_JLA_sufficiency']==_BOUNDARIES['JLA'] and comparison['UF1_UF6']=='NOT_ADJUDICATED'
           and comparison['Y_next']==_BOUNDARIES['Y_next'] and set(comparison['comparisons'])=={'B0','B2'},'comparison claim boundary differs')
    expected_refs=[item.input_ref for item in common.inputs]
    for method,arm in arms.items():
        _check(arm['method']==method and arm['common_evidence_digest']==common.digest and _same(arm['access_receipt'],common.receipt),'comparison common binding')
        _check([row['input_ref'] for row in arm['results']]==expected_refs,'received raw scope differs')
        _check(len(arm['join']['core_ledger'])==len(expected_refs),'join scope differs')
        _check(arm['status']=='INCOMPLETE_EVALUATION' if arm['failures'] else arm['status']=='EVALUATED','arm failure/status differs')
        _check(all(f['input_ref'] in expected_refs for f in arm['failures']),'failure outside raw scope')
        entries=[]
        for item,row,joined in zip(common.inputs,arm['results'],arm['join']['core_ledger']):
            _check(row['raw_digest']==_sha(item.raw) and joined['input_ref']==item.input_ref,'raw/join identity differs')
            entry=CoreEntry(joined['receipt_ref'],item.input_ref,row['result']);entries.append(entry)
            if entry.result is not None:_check(entry.result['input_sha256']==_sha(item.raw),'actual input hash differs')
        mappings={}
        for entry in entries:
            if entry.result is not None and entry.result['disposition']=='ADMIT':
                failed=any(f['input_ref']==entry.input_ref and f['phase']=='native_mapping' for f in arm['failures'])
                mappings[entry.receipt_ref]=(NativeMapping('PENDING',('NATIVE_MAPPING_EVALUATION_UNRESOLVED',)) if failed
                    else frozen_mapping(common.native,entry,common.exposures.get(entry.input_ref)))
        actual=analyze(entries,common.external_rows,mappings,common.policy,
            cohort_ref=arm['join']['cohort_ref'],snapshot_ref=arm['join']['snapshot_ref'])
        _check(_same(actual,arm['join']),'join/denominator differs from pure reconstruction')
    for method in ('B0','B2'):
        _check(_same(compare_full(arms['CPC_REFERENCE'],arms[method]),comparison['comparisons'][method]),'comparison result differs')
    core,external=project_b1(common)
    ref=arms['CPC_REFERENCE']['join']
    _check(_same(evaluate_b1(core,external,cohort_ref=ref['cohort_ref'],snapshot_ref=ref['snapshot_ref']),comparison['B1']),'B1 projection differs')


def _outcomes(view):
    _check(set(view)=={'derivations','outcomes','orphan_snapshot_files','counts'},'outcome view shape')
    derivations,rows=view['derivations'],view['outcomes']
    _check(len(derivations)<=MAX_NODES and len(rows)<=MAX_NODES,'outcome view bound')
    statuses=Counter(d['status'] for d in derivations)
    _check(set(statuses)<={'DERIVED','FAILED','PENDING','INPUTS_CAPTURED'},'derivation status invalid')
    expected={'received_derivations':len(derivations),'external_rows':len(rows),
        'failed_derivations':statuses['FAILED'],'pending_derivations':statuses['PENDING']+statuses['INPUTS_CAPTURED']}
    _check(_same(expected,view['counts']) and statuses['DERIVED']==len(rows),'derivation partition differs')
    _check(len({d['derivation_ref'] for d in derivations})==len(derivations) and len({r['row_ref'] for r in rows})==len(rows),'duplicate outcome identity')
    _check({d['outcome_ref'] for d in derivations if d['status']=='DERIVED'}=={r['row_ref'] for r in rows},'derived output refs differ')
    base={'derivation_ref','analysis_reference','controller_scope','requested_purpose','status','input_snapshots','output_snapshots','failure_stage'}
    for d in derivations:
        extra={'outcome_ref'} if d['status']=='DERIVED' else {'failure_code'} if d['status']=='FAILED' else set()
        _check(set(d)==base|extra,'derivation receipt shape differs')
        _check(not d['output_snapshots'] or d['status']=='DERIVED','non-derived output snapshots')
        stage=d['failure_stage'] if d['status']=='FAILED' else d['status']
        _check(set(d['input_snapshots'])==({'exposure','recipe'} if stage in {'INPUTS_CAPTURED','DERIVED'} else set()),'derivation input stage differs')
        _check(d['failure_stage'] in {'PENDING','INPUTS_CAPTURED'} if d['status']=='FAILED' else d['failure_stage'] is None,'derivation failure stage differs')
        if d['status']=='DERIVED':
            _check(set(d['output_snapshots'])=={'analysis','value','native_transport','recipe','exposure','outcome'},'derived output shape')
            _check(all(_same(d['input_snapshots'][k],d['output_snapshots'][k]) for k in ('exposure','recipe')),'derivation input/output link differs')
    return expected


def _lineage_matches(common,composite,derived,derivation,follow,selected,exposure,raw_exposure):
    """Verify supplied immutable lineage, including a historical derivation basis."""
    try:
        if exposure is None:return False
        expected={'experiment_id':composite.experiment_id,'experiment_version':composite.experiment_version,
            'unit_token':composite.unit_token,'record_id':composite.exposure_record_id}
        if any(exposure[k]!=v for k,v in expected.items()) or exposure['integrity']['content_digest']!=composite.exposure_digest:return False
        lineage=derived['lineage'];receipt=selected['transport']['receipt']
        if derivation['requested_purpose']!=composite.purpose:return False
        snapshot,event=receipt['snapshots'][0],receipt['occurrences'][0]
        if not (_same(lineage['source_snapshot'],snapshot) and _same(lineage['native_occurrence'],event)
                and _same(lineage['source_epoch'],receipt['source']) and _same(lineage['controller_scope'],derivation['controller_scope'])):return False
        if lineage['controller_scope']['source_epoch_ref']!=receipt['source']['source_epoch_ref']:return False
        if lineage['controller_scope']['ledger_ref']+':snapshots'!=lineage['capture_reference']['store_ref']:return False
        native_occ=common.native['view']['occurrences'][follow['occurrence_key']]
        if not _same(lineage['capture_reference'],native_occ['capture_snapshot']):return False
        if not _same(lineage['source_key'],[receipt['source']['source_epoch_ref'],event['standard_log_record_id'],snapshot['item_id']]):return False
        analysis_id=lineage['analysis_ref']
        allowed={common.native['analysis_ref']}|{e['data']['analysis_ref'] for e in common.native['events'] if e['event']=='ANALYSIS'}
        if analysis_id not in allowed:return False
        raw_analysis=bytes.fromhex(common.native['retained_local_snapshot_hex'][analysis_id])
        analysis_reference=SnapshotReference.from_mapping(derivation['analysis_reference'])
        if (analysis_reference.store_ref!=lineage['capture_reference']['store_ref'] or analysis_reference.snapshot_ref!=analysis_id
                or analysis_reference.sha256!=_sha(raw_analysis) or analysis_reference.byte_length!=len(raw_analysis)):return False
        document=decode_json_object(raw_analysis);basis=document['basis_sequence']
        if (document['analysis_ref']!=analysis_id or document['format']!='wss-episode-analysis-v1'
                or type(basis) is not int or not 1<=basis<=len(common.native['events']) or basis!=lineage['basis_sequence']
                or not _same(project_events(common.native['events'][:basis]),document['view'])):return False
        if document['view']['attempts'][composite.unit_token]['selected_followup']!=lineage['followup_ref']:return False
        outputs=derivation['output_snapshots'];raw=bytes.fromhex(selected['value_hex'])
        recipes=[raw_recipe for raw_recipe in common.auxiliary.values() if _sha(raw_recipe)==common.policy.recipe_digest]
        if not recipes:return False
        recipe=OutcomeRecipe(recipes[0]);state,value=recipe.score(raw)
        retained=common.native['retained_local_snapshot_hex']
        capture_ref=SnapshotReference.from_mapping(native_occ['capture_snapshot'])
        capture_raw=bytes.fromhex(retained[capture_ref.snapshot_ref]);capture=decode_json_object(capture_raw)
        if capture['format']!=CAPTURE_FORMAT or capture_ref.sha256!=_sha(capture_raw) or capture_ref.byte_length!=len(capture_raw):return False
        transport_ref=SnapshotReference.from_mapping(capture['raw_reference'])
        raw_transport=bytes.fromhex(retained[transport_ref.snapshot_ref])
        if transport_ref.sha256!=_sha(raw_transport) or transport_ref.byte_length!=len(raw_transport):return False
        transport=NativeReadTransport.from_json(raw_transport)
        if not _same(transport.to_mapping(),selected['transport']):return False
        source_value=next(blob.content for blob in transport.blobs if blob.ref==snapshot['value_bytes_ref'])
        expected_bytes={'analysis':raw_analysis,'value':raw,'recipe':recipes[0],
            'outcome':canonical_json_bytes(derived),'exposure':raw_exposure,'native_transport':raw_transport}
        for key,content in expected_bytes.items():
            ref=SnapshotReference.from_mapping(outputs[key])
            if ref.sha256!=_sha(content) or ref.byte_length!=len(content):return False
        return (source_value==raw and _same([state,value],[derived['measure_state'],derived['value']])
            and _same(receipt['source'],common.native['view']['context']['source'])
            and recipe.data['task_version_ref']==common.native['view']['context']['task_version_ref']
            and recipe.data['followup_item_digest']==snapshot['item_digest']
            and recipe.data['followup_presentation_digest']==snapshot['item_presentation_digest']
            and selected['value_digest']==_sha(raw)==snapshot['value_digest']==lineage['value_digest'])
    except (KeyError,IndexError,TypeError,ValueError,StopIteration,LedgerError):return False


def _trace(common,row,outcome_view):
    """One trace per core row, with all matching external ordinals retained."""
    trace={'input_ref':row['input_ref'],'primary_reason':row['primary_reason'],'linkage':'NOT_AVAILABLE',
           'external_ordinals':[],'core_row':row,'native':None,'outcome':None}
    composite=Composite.interpret(row.get('composite'))
    if composite is None:return trace
    matches=[i for i,r in enumerate(common.external_rows) if r.composite==composite]
    trace['external_ordinals']=matches
    attempt=common.native['view']['attempts'].get(composite.unit_token)
    if attempt is None:return trace
    follow=common.native['view']['followups'].get(attempt['selected_followup'])
    occurrence=common.native['view']['occurrences'].get(attempt['occurrence_key'])
    exposure=None
    if row['input_ref'] in common.exposures:
        try:exposure=exposure_metadata(common.exposures[row['input_ref']])
        except ContractError:pass
    invocation=None if exposure is None else common.native['view']['invocations'].get(exposure['payload']['invocation_id'])
    calls=[i for i in common.native['view']['invocations'].values() if i['attempt_ref']==composite.unit_token]
    trace['native']={'attempt':attempt,'task_occurrence':occurrence,'selected_followup':follow,
        'selected_source_summary':{k:v for k,v in common.native['selected_sources'].get(composite.unit_token,{}).items() if k not in {'value_hex','transport'}},
        'selected_followup_operation':None if follow is None else common.native['view']['operations'][follow['operation_ref']],
        'exposure_binding':None if exposure is None else {**{k:exposure[k] for k in ('record_id','experiment_id','experiment_version','unit_token')},
            'content_digest':exposure['integrity']['content_digest'],'raw_exposure_digest':_sha(common.exposures[row['input_ref']]),
            **{k:exposure['payload'][k] for k in ('invocation_id','artifact_version','enacted_condition')}},
        'invocation':invocation,'publications':[p for p in common.native['view']['publications'].values()
            if invocation is not None and p['invocation_ref']==invocation['invocation_ref']],
        'all_attempt_invocations':calls,'all_attempt_publications':[p for p in common.native['view']['publications'].values()
            if any(p['invocation_ref']==i['invocation_ref'] for i in calls)],
        'common_auxiliary':common.receipt['auxiliary']}
    derived=[r for r in outcome_view['outcomes'] if Composite.interpret(r['composite'])==composite]
    if len(matches)==1 and len(derived)==1:
        ext,derived=common.external_rows[matches[0]],derived[0]
        expected=external_from_outcome(derived)
        semantic=('row_ref','composite','scalar_type','integer_value','measure_state','rubric_id','rubric_version','recipe_digest','lineage_ref','shape_valid')
        equal=all(_same(getattr(ext,k).to_mapping() if k=='composite' and ext.composite else getattr(ext,k),
                        getattr(expected,k).to_mapping() if k=='composite' and expected.composite else getattr(expected,k)) for k in semantic)
        lineage=derived['lineage'];selected=common.native['selected_sources'].get(composite.unit_token,{})
        equal=equal and follow is not None and lineage['attempt_ref']==composite.unit_token and lineage['followup_ref']==attempt['selected_followup']
        equal=equal and lineage['operation_ref']==follow['operation_ref'] and lineage['value_digest']==selected.get('value_digest') and lineage['recipe_digest']==common.policy.recipe_digest
        derivations=[d for d in outcome_view['derivations'] if d['derivation_ref']==derived['lineage_ref'] and d['status']=='DERIVED' and d['outcome_ref']==derived['row_ref']]
        trace['outcome']={'row':derived,'derivations':derivations}
        if (equal and len(derivations)==1 and occurrence is not None and invocation is not None
                and _lineage_matches(common,composite,derived,derivations[0],follow,selected,exposure,common.exposures.get(row['input_ref']))):
            trace['linkage']='LINKED_SUPPLIED_LOCAL_EVIDENCE'
    return trace


def build_handoff(common: CommonEvidence, comparison: Mapping, outcome_view: Mapping, *, report_ref: str,
                  inventories: tuple[StoreInventory,...]=(), required_stores: Mapping|None=None,
                  adapter_views: Mapping|None=None) -> Mapping:
    """Pure report; never execute a study, core validation, or filesystem lookup."""
    _check(type(common) is CommonEvidence,'CommonEvidence required');require_identifier(report_ref,'report_ref')
    _check(len(canonical_json_bytes(comparison))+len(canonical_json_bytes(outcome_view))<=MAX_BYTES,'handoff input bound')
    _check(_same(project_events(common.native['events']),common.native['view']),'native projection differs')
    _verified_comparison(common,comparison)
    outcome_counts=_outcomes(outcome_view)
    view=common.native['view'];native_counts={key:len(view[key]) for key in _GRAINS}
    _check(_same(native_counts,view['counts']),'native grain counts differ')
    requirements={} if required_stores is None else plain_json(required_stores)
    _check(set(requirements)<=_ROLES and all(type(v) is list for v in requirements.values()),'required store scope invalid')
    _check(sum(map(len,requirements.values()))<=100,'required store count bound')
    required={(role,require_identifier(ref,'required store')) for role,refs in requirements.items() for ref in refs}
    _check(type(inventories) is tuple and len(inventories)<=100 and all(type(i) is StoreInventory for i in inventories),'typed inventories required')
    observed={(i.role,i.store_ref) for i in inventories}
    _check(len(observed)==len(inventories) and observed<=required,'inventory duplicate/undeclared store')
    missing=sorted(required-observed)
    inventory_complete=bool(required) and set(requirements)==_ROLES and all(requirements[r] for r in _ROLES) and not missing and all(i.complete for i in inventories)
    adapter_views={} if adapter_views is None else adapter_views
    _check(isinstance(adapter_views,Mapping) and len(adapter_views)<=100,'adapter scope bound/type')
    _check(len(canonical_json_bytes(adapter_views))<=MAX_BYTES,'adapter view byte bound')
    adapters=[]
    for batch_ref,batch in adapter_views.items():
        require_identifier(batch_ref,'adapter batch ref')
        _check(isinstance(batch,Mapping) and set(batch)=={'rows','received','results','counts','unresolved_receipts','failures',
            'evaluation_accounting_complete','accounting_complete','export_started','export','status','context_digest'},'adapter view shape')
        _check(type(batch['rows']) in (list,tuple) and len(batch['rows'])<=MAX_NODES,'adapter rows bound/type')
        counts={key:0 for key in ('ADMIT','REJECT','QUARANTINE','ERROR_INPUT','NOT_EVALUATED_CONFIG')};unresolved=[]
        for row in batch['rows']:
            entry=CoreEntry(row['receipt_ref'],row['input_ref'],row['result'])
            if entry.result is None:unresolved.append(row['receipt_ref'])
            else:counts['NOT_EVALUATED_CONFIG' if entry.result['disposition']=='ERROR_CONFIG' else entry.result['disposition']]+=1
        _check(_same(batch['received'],len(batch['rows'])) and _same(counts,batch['counts']) and _same(unresolved,batch['unresolved_receipts']),'separate adapter accounting differs')
        _check(type(batch['export_started']) is bool and type(batch['failures']) in (list,tuple)
               and (batch['export'] is None or isinstance(batch['export'],Mapping)),'adapter export/failure shape')
        pending=batch['export_started'] and batch['export'] is None
        complete=not unresolved and not batch['failures'] and not pending
        status='INCOMPLETE' if not complete else 'EXPORTED' if batch['export'] else 'OPEN'
        _check(batch['status']==status and _same(batch['accounting_complete'],complete)
            and _same(batch['evaluation_accounting_complete'],not unresolved)
            and _same(batch['results'],[row['result'] for row in batch['rows'] if row['result'] is not None])
            and (batch['export'] is None or batch['export_started']), 'separate adapter completeness differs')
        adapters.append({'batch_ref':batch_ref,'received':batch['received'],'counts':counts,'unresolved':unresolved,'view':batch,
                         'scope':'separate batch; may overlap comparison raw inputs; do not sum'})
    needed=[]
    for event in common.native['events']:
        key={'INGESTION':'raw_snapshot','OBSERVATION':'capture_snapshot','ANALYSIS':'analysis_snapshot'}.get(event['event'])
        if key and event['data'].get(key) is not None:
            reference=event['data'][key];needed.append(('CONTROLLER',reference))
            if key=='capture_snapshot':
                ref_value=SnapshotReference.from_mapping(reference)
                raw=bytes.fromhex(common.native['retained_local_snapshot_hex'][ref_value.snapshot_ref])
                _check(_sha(raw)==ref_value.sha256 and len(raw)==ref_value.byte_length,'capture manifest byte link differs')
                capture=decode_json_object(raw)
                _check(set(capture)=={'format','raw_reference','blob_references','metadata_issues'} and capture['format']==CAPTURE_FORMAT,'capture manifest shape differs')
                needed.extend(('CONTROLLER',item) for item in [capture['raw_reference'],*capture['blob_references']])
    for derivation in outcome_view['derivations']:
        needed.extend(('OUTCOME',r) for key in ('input_snapshots','output_snapshots') for r in derivation[key].values())
        if derivation['analysis_reference'] is not None:needed.append(('CONTROLLER',derivation['analysis_reference']))
    for batch in adapter_views.values():
        needed.extend(('ADAPTER',row[key]) for row in batch['rows'] for key in ('raw_reference','returned_reference','requested_ref_reference') if row.get(key) is not None)
    verified={(i.role,canonical_json_bytes(r['reference'])) for i in inventories for r in i.references if r['status']=='MATCH'}
    gaps=[{'role':role,'reference':reference} for role,reference in needed if (role,canonical_json_bytes(reference)) not in verified]
    inventory_complete=inventory_complete and not gaps
    ref=comparison['arms']['CPC_REFERENCE']['join']
    source_map=[_trace(common,row,outcome_view) for row in ref['core_ledger']]
    positive=next((i for i,row in enumerate(source_map) if row['primary_reason']=='JOINED' and row['linkage']=='LINKED_SUPPLIED_LOCAL_EVIDENCE'),None)
    hold=next((i for i,row in enumerate(source_map) if row['primary_reason']=='NATIVE_MAPPING_HOLD' and row['linkage']=='LINKED_SUPPLIED_LOCAL_EVIDENCE'),None)
    flags=[]
    if not inventory_complete:flags.append('INVENTORY_SCOPE_INCOMPLETE')
    if any(a['status']!='EVALUATED' or not a['join']['complete_for_declared_snapshot'] for a in comparison['arms'].values()):flags.append('COMPARISON_INCOMPLETE_OR_SUPERSEDED')
    if any(c['status']!='MATCH' for c in comparison['comparisons'].values()):flags.append('COMPARISON_DIFFERENCE_OR_UNRESOLVED')
    if outcome_counts['failed_derivations'] or outcome_counts['pending_derivations']:flags.append('DERIVATION_FAILURE_OR_PENDING')
    if any(a['unresolved'] or a['view']['status']=='INCOMPLETE' for a in adapters):flags.append('SEPARATE_ADAPTER_INCOMPLETE')
    if any(row['primary_reason']=='JOINED' and row['linkage']!='LINKED_SUPPLIED_LOCAL_EVIDENCE' for row in source_map):flags.append('JOINED_SOURCE_LINKAGE_INCOMPLETE')
    if outcome_view['orphan_snapshot_files'] or any(f['classification']=='ORPHAN' for i in inventories for f in i.files):flags.append('ORPHAN_SNAPSHOTS_PRESENT')
    if any(o['status'] in {'PENDING','HELD'} for o in view['operations'].values()) or any(not i['settled'] for i in view['invocations'].values()):flags.append('NATIVE_OPERATION_OR_INVOCATION_UNRESOLVED')
    admitted={Composite.interpret(row.get('composite')) for row in ref['core_ledger'] if row['core_disposition']=='ADMIT'}
    linked_attempts={c.unit_token for c in admitted if c is not None}
    source_only=[{'attempt_ref':key,'status':'NO_ADMITTED_EXPORT_LINK',
        'submission_status':'NOT_SUBMITTED_IN_DECLARED_COHORT' if not common.inputs else 'UNKNOWN_WITHOUT_EXPLICIT_LINK',
        'core_verdict':None} for key in view['attempts'] if key not in linked_attempts]
    external_orphans=[i for i,row in enumerate(common.external_rows) if row.composite is None or row.composite not in admitted]
    inventory_rows=[i.to_mapping() for i in inventories]
    orphan_counts={i.role+':'+i.store_ref:sum(f['classification']=='ORPHAN' for f in i.files) for i in inventories}
    result={'format':'wss-handoff-v1','report_ref':report_ref,'status':'DIAGNOSTIC_INCOMPLETE' if flags else 'RECONCILED_DECLARED_SCOPE',
        'reason_flags':flags,'common_evidence_digest':common.digest,'access_receipt':common.receipt,
        'scope':{'cohort_ref':ref['cohort_ref'],'snapshot_ref':ref['snapshot_ref'],'native_analysis_ref':common.native['analysis_ref'],
                 'captured_head':common.native['current_head'],'analysis_history_is_prefix_only':True},
        'counts':{'native':native_counts,'native_operation_statuses':dict(Counter(o['status'] for o in view['operations'].values())),
            'native_ingestion_statuses':dict(Counter(o['status'] for o in view['ingestions'].values())),
            'invocations_ever_published':sum(i['ever_published'] for i in view['invocations'].values()),
            'invocations_publication_unresolved':sum(i['publication_unresolved'] for i in view['invocations'].values()),
            'invocation_terminal_stages':dict(Counter(i['stage'] for i in view['invocations'].values())),
            'post_close_followup_revisions':sum(f['post_close_revision'] for f in view['followups'].values()),
            'outcomes':outcome_counts,'comparison_per_arm':{m:a['join']['counts'] for m,a in comparison['arms'].items()},
            'outcome_store_orphan_files':len(outcome_view['orphan_snapshot_files']),
            'inventory_orphans_per_store':orphan_counts,'external_orphan_ordinals':external_orphans},
        'ledgers':{'native':view,'comparison':comparison,'outcomes':outcome_view,'source_only_attempts':source_only,'separate_adapter_batches':adapters},
        'inventory':{'requirements':requirements,'missing':[list(pair) for pair in missing],
            'reference_coverage_gaps':gaps,'scope_declared':bool(required),'complete_for_declared_roots':inventory_complete,'stores':inventory_rows},
        'source_map':source_map,
        'examples':{'positive':{'status':'NOT_AVAILABLE' if positive is None else 'AVAILABLE','source_map_ordinal':positive},
                    'native_hold':{'status':'NOT_AVAILABLE' if hold is None else 'AVAILABLE','source_map_ordinal':hold}},
        'boundaries':_BOUNDARIES,'four_D2_counterexamples':_NEGATIVES,
        'interpretation':'All counts have distinct grain/scope. Reconciliation is engineering only; examples may be absent. No UF5/utility/rights/release inference.'}
    _check(len(canonical_json_bytes(result))<=MAX_BYTES,'report output bound')
    return freeze_json(result)


def reader_candidate(report: Mapping) -> Mapping:
    """Fixed fields and aggregate integers only; never copy arbitrary input text."""
    _check(report.get('format')=='wss-handoff-v1','handoff required')
    counts=report['counts'];arms={}
    def count(value):
        _check(type(value) is int and 0<=value<=100000,'reader candidate requires bounded integer counts')
        return value
    keys={'core_buckets':('ADMIT','REJECT','QUARANTINE','ERROR_INPUT','NOT_EVALUATED_CONFIG'),
          'admitted_mapping':('PENDING','HOLD','ELIGIBLE'),
          'eligible_terminals':('ADMISSION_COMPOSITE_AMBIGUOUS','EXTERNAL_COMPOSITE_AMBIGUOUS','EXTERNAL_MISSING','EXTERNAL_MEASURE_INVALID','JOINED')}
    _check(report['status'] in {'DIAGNOSTIC_INCOMPLETE','RECONCILED_DECLARED_SCOPE'},'reader state invalid')
    for method in ('CPC_REFERENCE','B0','B2'):
        c=counts['comparison_per_arm'][method]
        arms[method]={key:{k:count(c[key][k]) for k in allowed} for key,allowed in keys.items()}
    result={'format':'wss-reader-candidate-v1','status':'CANDIDATE_FOR_REVIEW_NOT_RELEASE_AUTHORIZED',
        'counts':{'native':{key:count(counts['native'][key]) for key in _GRAINS},'per_arm':arms,
            'derivations':{k:count(counts['outcomes'][k]) for k in ('received_derivations','external_rows','failed_derivations','pending_derivations')}},
        'engineering_state':report['status'],'boundaries':_BOUNDARIES,
        'four_D2_counterexamples':[{('archived_case_id' if key=='input_ref' else key):value for key,value in row.items()} for row in _NEGATIVES]}
    return freeze_json(result)


def render_markdown(report: Mapping, *, reader=False) -> str:
    candidate=reader_candidate(report)
    text='# WSS offline handoff\n\n'+('Reader candidate: review only; release is not authorized.\n\n' if reader else 'Restricted local engineering handoff; supplied synthetic evidence only.\n\n')
    text+='| Native grain | Count |\n|---|---|\n'
    text+=''.join('| '+key+' | '+str(candidate['counts']['native'][key])+' |\n' for key in _GRAINS)
    text+='\nCounts describe separate grains; they must not be summed into one N.\n\n'
    if not reader:
        text+='Positive and native hold examples use source-map ordinals in this exact cohort.\n\n'
        text+='```json\n'+canonical_json_bytes(report['examples']).decode()+'\n```\n\n'
        text+='See source_map.json and ledgers.json for typed lineage and all received records, including missing/pending/orphans.\n\n'
    text+='Y_next: NOT_MEASURED / NOT_VALIDATED_HERE. UF1–UF6: NOT_ADJUDICATED. JLA: INSUFFICIENT_EVIDENCE_UNCHANGED.\n\n'
    text+='Four archived D2 cases D3-00014/00029/00044/00059 remain ADMIT / primary JOINED / physical MISMATCH; actual prompt AND generation differ; not mitigated.\n'
    return text


_FILES={'RESTRICTED':{'report.json','ledgers.json','source_map.json','traces.json','summary.md'},
        'READER_CANDIDATE':{'reader_candidate.json','reader_candidate.md'}}
_REPORT_FIELDS={'format','report_ref','status','reason_flags','common_evidence_digest','access_receipt','scope','counts',
    'ledgers','inventory','source_map','examples','boundaries','four_D2_counterexamples','interpretation'}


def _report_shape(report):
    _check(set(report)==_REPORT_FIELDS and report['format']=='wss-handoff-v1','closed report required')
    _check(set(report['ledgers'])=={'native','comparison','outcomes','source_only_attempts','separate_adapter_batches'},'report ledger allowlist')
    _check(_same(report['boundaries'],_BOUNDARIES) and _same(report['four_D2_counterexamples'],_NEGATIVES),'report boundaries differ')


def _reader_shape(candidate):
    fake={'format':'wss-handoff-v1','status':candidate['engineering_state'],
        'counts':{'native':candidate['counts']['native'],'comparison_per_arm':candidate['counts']['per_arm'],
                  'outcomes':candidate['counts']['derivations']}}
    _check(_same(reader_candidate(fake),candidate),'reader candidate exceeds closed allowlist')
    return fake


def write_handoff(report: Mapping, root, *, mode='RESTRICTED') -> Mapping:
    """Exclusive new root; explicit write only. Failed partial roots stay intact."""
    _check(mode in _FILES and report.get('format')=='wss-handoff-v1','handoff mode/report invalid')
    _report_shape(report)
    if mode=='RESTRICTED':
        payload={'report.json':canonical_json_bytes(report),'ledgers.json':canonical_json_bytes(report['ledgers']),
            'source_map.json':canonical_json_bytes(report['source_map']),'traces.json':canonical_json_bytes(report['examples']),
            'summary.md':render_markdown(report).encode()}
    else:payload={'reader_candidate.json':canonical_json_bytes(reader_candidate(report)),
                  'reader_candidate.md':render_markdown(report,reader=True).encode()}
    _check(sum(map(len,payload.values()))<=MAX_BYTES and all(len(raw)<=MAX_FILE for raw in payload.values()),'handoff payload bound')
    target=_real_directory(root,exists=False);target.mkdir(mode=0o700,exist_ok=False)
    _new_file(target/'STARTED.json',canonical_json_bytes({'format':'wss-handoff-write-v1','mode':mode,'status':'STARTED'}))
    hashes={}
    for name,raw in payload.items():
        _new_file(target/name,raw)
        _check(_read_file(target/name,MAX_FILE)==raw,'handoff readback differs')
        hashes[name]=_sha(raw)
    manifest=canonical_json_bytes({'format':'wss-handoff-manifest-v1','mode':mode,'files':hashes})
    _new_file(target/'MANIFEST.json',manifest)
    _new_file(target/'COMPLETED.json',canonical_json_bytes({'format':'wss-handoff-write-v1','mode':mode,
        'status':'COMPLETED','manifest_sha256':_sha(manifest),'release':'NOT_AUTHORIZED'}))
    _fsync_directory(target);_fsync_directory(target.parent)
    return verify_handoff(target,mode=mode)


def verify_handoff(root, *, mode='RESTRICTED') -> Mapping:
    _check(mode in _FILES,'handoff mode invalid')
    target=_real_directory(root,exists=True)
    _check(stat.S_IMODE(target.stat().st_mode)==0o700,'handoff directory permissions differ')
    expected=_FILES[mode]|{'STARTED.json','MANIFEST.json','COMPLETED.json'}
    _check({p.name for p in target.iterdir()}==expected,'handoff file inventory incomplete/unexpected')
    for path in target.iterdir():
        meta=path.lstat()
        _check(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1 and stat.S_IMODE(meta.st_mode)==0o600,'handoff file type/link/permissions differ')
    start=decode_json_object(_read_file(target/'STARTED.json',MAX_FILE))
    complete=decode_json_object(_read_file(target/'COMPLETED.json',MAX_FILE))
    raw=_read_file(target/'MANIFEST.json',MAX_FILE);manifest=decode_json_object(raw)
    _check(_same(start,{'format':'wss-handoff-write-v1','mode':mode,'status':'STARTED'}),'handoff start invalid')
    _check(_same(complete,{'format':'wss-handoff-write-v1','mode':mode,'status':'COMPLETED','manifest_sha256':_sha(raw),'release':'NOT_AUTHORIZED'}),'handoff completion invalid')
    _check(set(manifest)=={'format','mode','files'} and manifest['format']=='wss-handoff-manifest-v1'
        and manifest['mode']==mode and set(manifest['files'])==_FILES[mode],'handoff manifest scope invalid')
    total=0
    for name,digest in manifest['files'].items():
        raw=_read_file(target/name,MAX_FILE);total+=len(raw)
        _check(total<=MAX_BYTES and _sha(raw)==digest,'handoff payload hash/bound differs')
    if mode=='READER_CANDIDATE':
        candidate=decode_json_object(_read_file(target/'reader_candidate.json',MAX_FILE))
        fake=_reader_shape(candidate)
        _check(_read_file(target/'reader_candidate.md',MAX_FILE)==render_markdown(fake,reader=True).encode(),'reader markdown differs')
    else:
        report=decode_json_object(_read_file(target/'report.json',MAX_FILE));_report_shape(report)
        for name,key in (('ledgers.json','ledgers'),('source_map.json','source_map'),('traces.json','examples')):
            _check(_read_file(target/name,MAX_FILE)==canonical_json_bytes(report[key]),'restricted duplicated view differs')
        _check(_read_file(target/'summary.md',MAX_FILE)==render_markdown(report).encode(),'restricted summary differs')
    return freeze_json({'status':'VERIFIED_LOCAL_PAYLOAD_ONLY','mode':mode,'files':len(expected),
        'manifest_sha256':complete['manifest_sha256'],'release':'NOT_AUTHORIZED'})
