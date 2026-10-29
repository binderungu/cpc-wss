"""Complete supplied-evidence OFFLINE orchestration; no native/provider connector.

Ports are trusted operator callables, not authority proofs or dynamic plugins.
No construction/import performs IO. run_offline performs explicit local writes,
CPC evaluation and local publication, with a cooperative no-network/process guard.
"""
from __future__ import annotations
from dataclasses import dataclass,field,asdict
from collections.abc import Callable,Mapping
from pathlib import Path
from contextlib import contextmanager
import hashlib,json,os,sys,threading,stat
from .primitives import (ContractError,canonical_json_bytes,plain_json,freeze_json,
 require_identifier,require_digest,require_int,require_bool,require_mapping,decode_json_object)
from .native_contract import SourceIdentity,ActorBinding,NativeTarget
from .controller import OfflineController,ControllerContext,RESOURCES,CONFIGS
from .ledger import LedgerScope,SnapshotReference,_real_directory,_fsync_directory,_checked_fd
from .renderer import CatalogSnapshot,ResolutionBinding
from .capture import LocalClock
from .producer import ProducerPolicy,ProductionResult,produce
from .producer_references import ProducerReferenceIndex
from .outcomes import OutcomeRecipe,OutcomeStore,external_from_outcome
from .cpc_adapter import AdmissionContext,CPCAdapter,AdapterStopped
from .join import JoinPolicy
from .native_transport import NativeReadTransport,MAX_TRANSPORT_BYTES
from .baselines import CommonEvidence,RawInput,capture_native,run_comparison
from .reporting import capture_inventory,capture_producer_inventory,build_handoff,write_handoff,verify_handoff

MAX_RECEIVED_BYTES=64*1024*1024
_ACTIVE=0
_INSTALLED=False
_GUARD_LOCK=threading.RLock()
def _audit(event,args):
 if _ACTIVE and (event.startswith(('socket.','sqlite3.')) or event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn'}):
  raise PermissionError('OFFLINE_RUNNER_EXTERNAL_IO_BLOCKED')
@contextmanager
def offline_guard():
 """Process-wide cooperative guard while active; not an adversarial sandbox."""
 global _ACTIVE,_INSTALLED
 with _GUARD_LOCK:
  if not _INSTALLED:sys.addaudithook(_audit);_INSTALLED=True
  _ACTIVE+=1
 try:yield
 finally:
  with _GUARD_LOCK:_ACTIVE-=1

def _sha(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()
def _positive(v,name,maximum):
 require_int(v,name,minimum=1)
 if v>maximum:raise ContractError(name+': limit exceeded')
def _write(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 _fsync_directory(Path(path).parent)
def _json(path,obj):_write(path,canonical_json_bytes(obj))
def _context(m):
 require_mapping(m,'context',required=('source','actor','task_target','followup_target','task_version_ref','context_version_ref','clean_interval_evidence_ref','prior_operations_evidence_ref','sole_writer_evidence_ref','pending_facts'))
 return ControllerContext(SourceIdentity.from_mapping(m['source']),ActorBinding.from_mapping(m['actor']),NativeTarget.from_mapping(m['task_target']),NativeTarget.from_mapping(m['followup_target']),m['task_version_ref'],m['context_version_ref'],m['clean_interval_evidence_ref'],m['prior_operations_evidence_ref'],m['sole_writer_evidence_ref'],m['pending_facts'])

@dataclass(frozen=True)
class EpisodePlan:
 episode_ref:str
 logical_resource:str
 config_id:str
 task_value_digest:str
 followup_value_digest:str
 publications:int=1
 outcome_owner_ordinal:int=1
 def __post_init__(self):
  require_identifier(self.episode_ref,'episode_ref')
  for suffix in [':core',':TASK',':FOLLOWUP',':settled']:require_identifier(self.episode_ref+suffix,'generated_episode_ref')
  if self.logical_resource not in RESOURCES or self.config_id not in CONFIGS:raise ContractError('episode resource/config unsupported')
  require_digest(self.task_value_digest,'task_value_digest');require_digest(self.followup_value_digest,'followup_value_digest')
  _positive(self.publications,'publications',16);_positive(self.outcome_owner_ordinal,'outcome_owner_ordinal',self.publications)
 @classmethod
 def from_mapping(cls,m):return cls(**require_mapping(m,'episode',required=tuple(cls.__dataclass_fields__)))

@dataclass(frozen=True)
class RunnerConfig:
 scope:LedgerScope
 context:ControllerContext
 episodes:tuple[EpisodePlan,...]
 purpose:str
 evidence_class:str='SYNTHETIC_OFFLINE_FIXTURE'
 max_operations:int=6
 max_observations:int=18
 max_publications:int=4
 def __post_init__(self):
  if type(self.scope) is not LedgerScope or type(self.context) is not ControllerContext:raise ContractError('typed scope/context required')
  if self.scope.source_epoch_ref!=self.context.source.source_epoch_ref or self.context.readiness_issues():raise ContractError('runner context unresolved or epoch differs')
  require_identifier(self.purpose,'purpose')
  for suffix in [':admission',':common',':cohort',':snapshot',':handoff']:require_identifier(self.scope.run_ref+suffix,'generated_run_ref')
  require_identifier(self.scope.ledger_ref+':snapshots','generated_controller_store_ref')
  if self.evidence_class not in {'SYNTHETIC_OFFLINE_FIXTURE','REPORTED_NATIVE_READ'}:raise ContractError('unsupported supplied evidence class')
  if self.scope.purpose in {'SYNTHETIC_OFFLINE_FIXTURE','REPORTED_NATIVE_READ'} and self.scope.purpose!=self.evidence_class:raise ContractError('source-labeled scope contradicts evidence class')
  if not isinstance(self.episodes,(tuple,list)) or not 1<=len(self.episodes)<=100 or any(type(e) is not EpisodePlan for e in self.episodes):raise ContractError('bounded episode plan required')
  object.__setattr__(self,'episodes',tuple(self.episodes))
  if len({e.episode_ref for e in self.episodes})!=len(self.episodes):raise ContractError('duplicate episode refs')
  _positive(self.max_operations,'max_operations',200);_positive(self.max_observations,'max_observations',600);_positive(self.max_publications,'max_publications',96)
  if len(self.episodes)*2>self.max_operations or len(self.episodes)*2>self.max_observations or sum(e.publications for e in self.episodes)>self.max_publications:raise ContractError('plan exceeds operation/publication budget')
 def to_mapping(self):
  return {'scope':self.scope.to_mapping(),'context':self.context.to_mapping(),'episodes':[asdict(e) for e in self.episodes],**{n:getattr(self,n) for n in ['purpose','evidence_class','max_operations','max_observations','max_publications']}}
 @classmethod
 def from_mapping(cls,m):
  m=require_mapping(m,'runner config',required=tuple(cls.__dataclass_fields__))
  return cls(LedgerScope(**m['scope']),_context(m['context']),tuple(EpisodePlan.from_mapping(e) for e in m['episodes']),m['purpose'],m['evidence_class'],m['max_operations'],m['max_observations'],m['max_publications'])
 @classmethod
 def from_bytes(cls,raw):return cls.from_mapping(decode_json_object(raw,'runner config'))

@dataclass(frozen=True)
class OperationRequest:
 episode_ref:str
 kind:str
 operation_ref:str
 attempt_ref:str|None
 log_watermark:int
 controlled_value_digest:str
 context:ControllerContext=field(repr=False)
@dataclass(frozen=True)
class ObservationInput:
 slot_ms:int
 raw:bytes=field(repr=False)
 reported_exit_code:int=0
 reported_close_confirmed:bool=True
 def __post_init__(self):
  require_int(self.slot_ms,'slot_ms');require_bool(self.reported_close_confirmed,'reported_close_confirmed')
  if type(self.raw) is not bytes or len(self.raw)>MAX_TRANSPORT_BYTES:raise ContractError('bounded immutable transport bytes required')
  if type(self.reported_exit_code) is not int:raise ContractError('exit code must be integer')
@dataclass(frozen=True)
class OperationInput:
 completion_known:bool
 completion_evidence_ref:str
 observations:tuple[ObservationInput,...]
 def __post_init__(self):
  require_bool(self.completion_known,'completion_known');require_identifier(self.completion_evidence_ref,'completion_evidence_ref')
  if not isinstance(self.observations,(tuple,list)) or len(self.observations)>3 or any(type(x) is not ObservationInput for x in self.observations):raise ContractError('at most three typed supplied observations')
  object.__setattr__(self,'observations',tuple(self.observations))
@dataclass(frozen=True)
class HelpRequest:
 episode:EpisodePlan
 attempt_ref:str
 publication_ordinal:int
 invocation_ref:str
 context:ControllerContext=field(repr=False)
@dataclass(frozen=True)
class HelpInputs:
 assignment_raw:bytes=field(repr=False)
 resolution_raw:bytes=field(repr=False)
 policy:ProducerPolicy=field(repr=False)
 prompt_raw:bytes=field(repr=False)
 generation_raw:bytes=field(repr=False)
 catalog:CatalogSnapshot=field(repr=False)
 binding:ResolutionBinding=field(repr=False)
 clock:LocalClock|None=field(default=None,repr=False)
@dataclass(frozen=True)
class OutcomeRequest:
 episode:EpisodePlan
 attempt_ref:str
 assignment_raw:bytes=field(repr=False)
 resolution_raw:bytes=field(repr=False)
 exposure_raw:bytes=field(repr=False)
 outcome:Mapping=field(repr=False)
 purpose:str=''
@dataclass(frozen=True)
class RunnerPorts:
 operation:Callable[[OperationRequest],OperationInput]=field(repr=False)
 help_inputs:Callable[[HelpRequest],HelpInputs]=field(repr=False)
 sign_outcome:Callable[[OutcomeRequest],bytes]=field(repr=False)
 admission_context:Callable[[],AdmissionContext]=field(repr=False)
 recipe:OutcomeRecipe=field(repr=False)
 def __post_init__(self):
  if any(not callable(getattr(self,n)) for n in ['operation','help_inputs','sign_outcome','admission_context']) or type(self.recipe) is not OutcomeRecipe:raise ContractError('explicit typed ports and approved-domain recipe required')
@dataclass(frozen=True)
class RunnerResult:
 root:str
 status:str
 phase:str
 error_type:str|None
 counts:Mapping
 report_status:str|None
 def to_mapping(self):return plain_json({'format':'wss-worked-runner-result-v1','root':self.root,'status':self.status,'phase':self.phase,'error_type':self.error_type,'counts':self.counts,'report_status':self.report_status,'mode':'OFFLINE_SUPPLIED_EVIDENCE','native_or_provider_connector_used':False,'scientific_or_release_approval':False})

def _collect_auxiliary(productions,initial,remaining):
 """Bound size/count BEFORE reading any producer bytes; retain no truncation."""
 auxiliary=dict(initial);seen=0
 for number,p in enumerate(productions):
  for path in sorted(Path(p.root).rglob('*')):
   meta=path.lstat()
   if stat.S_ISDIR(meta.st_mode):continue
   if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1:raise RunnerStopped('producer tree nonregular/link refused')
   seen+=1
   if seen>10000 or meta.st_size>remaining:raise RunnerStopped('common auxiliary input budget exceeded before read')
   fd=_checked_fd(path,os.O_RDONLY)
   with os.fdopen(fd,'rb') as stream:raw=stream.read(remaining+1)
   if len(raw)!=meta.st_size or len(raw)>remaining:raise RunnerStopped('producer bytes changed or exceed budget')
   remaining-=len(raw);auxiliary['producer'+str(number)+':'+str(path.relative_to(p.root))]=raw
 return auxiliary

class RunnerStopped(ContractError):pass
class _Run:
 def __init__(self,root,cfg,ports):
  self.root=root;self.cfg=cfg;self.ports=ports;self.phase='INITIALIZE';self.seq=0
  self.controller=None;self.outcomes=None;self.adapter=None;self.productions=[];self.completed=[]
  self.operations=0;self.observations=0;self.publications=0;self.watermarks={'TASK':0,'FOLLOWUP':0};self.received_bytes=0;self.raws=[];self.exposures={};self.external=[];self.auxiliary={}
 def event(self,name,data):
  self.seq+=1;_json(self.root/'events'/(str(self.seq).zfill(5)+'_'+name+'.json'),{'event':name,'phase':self.phase,'data':data})
 def _retain(self,label,raw):
  if type(raw) is not bytes:raise RunnerStopped('immutable supplied bytes required')
  if self.received_bytes+len(raw)>MAX_RECEIVED_BYTES:raise RunnerStopped('received byte budget exceeded')
  self.received_bytes+=len(raw)
  path=self.root/'received'/(str(self.seq+1).zfill(5)+'_'+label+'.bin');_write(path,raw)
  self.event('INPUT_RETAINED',{'label':label,'relative_path':str(path.relative_to(self.root)),'sha256':_sha(raw),'byte_length':len(raw)})
 def observe(self,episode,kind,attempt=None):
  self.phase=kind+'_INPUT';c=self.controller
  if self.operations>=self.cfg.max_operations:raise RunnerStopped('operation budget exhausted')
  opportunity=c.opportunity(note_ref=episode.episode_ref+':'+kind)
  dg=episode.task_value_digest if kind=='TASK' else episode.followup_value_digest
  op=c.begin_operation(opportunity,kind,controlled_value_digest=dg,log_watermark=self.watermarks[kind],attempt_ref=attempt,logical_resource=episode.logical_resource if kind=='TASK' else None,config_id=episode.config_id if kind=='TASK' else None)
  self.operations+=1;self.event('PROSPECTIVE_OPERATION',{'episode':episode.episode_ref,'kind':kind,'operation_ref':op,'watermark':self.watermarks[kind]})
  supplied=self.ports.operation(OperationRequest(episode.episode_ref,kind,op,attempt,self.watermarks[kind],dg,self.cfg.context))
  if type(supplied) is not OperationInput:raise RunnerStopped('operation port returned unsupported input')
  # Retain every received raw item first, including unused/invalid items after a terminal result.
  for i,item in enumerate(supplied.observations):self._retain(kind+'_'+str(i),item.raw)
  c.record_completion(op,known=supplied.completion_known,evidence_ref=supplied.completion_evidence_ref)
  last=None;task_anchor=None
  for position,item in enumerate(supplied.observations):
   if self.observations>=self.cfg.max_observations:raise RunnerStopped('observation budget exhausted')
   self.observations+=1;ack=c.observe(op,item.slot_ms,item.raw);self.event('OBSERVATION',{'operation_ref':op,'slot_ms':item.slot_ms,'reported_process_exit':item.reported_exit_code,'reported_close':item.reported_close_confirmed,'ack':ack})
   if not supplied.completion_known or item.reported_exit_code!=0 or not item.reported_close_confirmed:raise RunnerStopped('source completion/process/close unresolved')
   transport=NativeReadTransport.from_json(item.raw)
   if transport.evidence_class!=self.cfg.evidence_class:raise RunnerStopped('supplied evidence class differs')
   if ack['status']=='WAIT' and not ack['acknowledged']:
    if last is not None:
     self.event('SOURCE_PROGRESS_REFUSED',{'operation_ref':op,'reason':'POST_CAPTURE_NO_MATCH','retained_prior_positive':True})
     raise RunnerStopped('post-capture NO_MATCH conflict')
    continue
   if ack['status'] not in {'ACCEPTED','DUPLICATE'} or not ack['acknowledged']:raise RunnerStopped('source observation held')
   last=ack;self.watermarks[kind]=transport.receipt.cursor_end
   if kind=='TASK' and ack.get('anchor') is not None:task_anchor=ack['anchor']['attempt_ref']
  if last is None:raise RunnerStopped('native-shaped anchor unavailable')
  return task_anchor if kind=='TASK' else attempt
 def episode(self,e):
  c=self.controller;attempt=self.observe(e,'TASK');helps=[]
  for ordinal in range(1,e.publications+1):
   if self.publications>=self.cfg.max_publications:raise RunnerStopped('publication-attempt budget exhausted')
   self.phase='HELP_PREPARATION'
   inv=c.receive_help(attempt,logical_resource=e.logical_resource,config_id=e.config_id)
   self.event('HELP_PREPARATION_INTENT',{'episode':e.episode_ref,'attempt':attempt,'publication_ordinal':ordinal,'invocation_ref':inv})
   current=c.view()['invocations'][inv]
   if current['settled']:raise RunnerStopped('help precondition refused')
   try:
    h=self.ports.help_inputs(HelpRequest(e,attempt,ordinal,inv,self.cfg.context))
    if type(h) is not HelpInputs:raise RunnerStopped('help port returned unsupported input')
    for label,raw in [('assignment',h.assignment_raw),('resolution',h.resolution_raw)]:self._retain(label,raw)
   except Exception:
    c.finish_invocation(inv,publication='NONE',evidence_ref='runner:help-preparation-failed')
    self.event('HELP_PREPARATION_FAILED',{'invocation_ref':inv,'publication':'NONE'})
    raise
   self.publications+=1;self.phase='PRODUCE';p=produce(c,attempt,logical_resource=e.logical_resource,config_id=e.config_id,root=self.root/'producers'/('producer-'+str(self.publications).zfill(4)),policy=h.policy,resolution_raw=h.resolution_raw,prompt_raw=h.prompt_raw,generation_raw=h.generation_raw,catalog=h.catalog,binding=h.binding,clock=h.clock,preallocated_invocation_ref=inv)
   self.productions.append(p);self.event('PRODUCTION_RETURNED',asdict(p))
   if p.status!='COMPLETE' or p.publication!='PUBLISHED' or not p.controller_reconciled or p.exposure_reference is None:raise RunnerStopped('production incomplete or publication unresolved')
   index=ProducerReferenceIndex.open_readonly(p.root,invocation_ref=p.invocation_ref,call_ref=p.call_ref);raw=index.store.get(p.exposure_reference)
   helps.append((h,p,raw))
  self.observe(e,'FOLLOWUP',attempt);self.phase='OUTCOME'
  analysis=c.analysis_snapshot(reason=e.episode_ref+':settled');h,p,exposure=helps[e.outcome_owner_ordinal-1]
  row=self.outcomes.derive(c,analysis,exposure,self.ports.recipe,self.cfg.purpose);self.external.append(external_from_outcome(row))
  self.phase='OUTCOME_SIGNING';signed=self.ports.sign_outcome(OutcomeRequest(e,attempt,h.assignment_raw,h.resolution_raw,exposure,row,self.cfg.purpose));self._retain('signed_outcome',signed)
  records=[decode_json_object(x) for x in (h.assignment_raw,h.resolution_raw,exposure,signed)]
  profile=plain_json(h.policy.profile)
  chain=canonical_json_bytes({'contract_version':'2.0.1','profile_id':profile['profile_id'],'profile_version':profile['profile_version'],'case_id':e.episode_ref,'records':records})
  ref=e.episode_ref+':core';self._retain('complete_chain',chain);self.raws.append(RawInput(ref,chain));self.exposures[ref]=exposure
  episode_record={'episode_ref':e.episode_ref,'attempt_ref':attempt,'publication_invocations':[x[1].invocation_ref for x in helps],'outcome_owner_invocation':p.invocation_ref,'source_owned_outcome_key':row['composite']['outcome_key'],'core_input_ref':ref,'unsubmitted_exposures':[x[1].invocation_ref for n,x in enumerate(helps,1) if n!=e.outcome_owner_ordinal]}
  self.event('EPISODE_COMPLETED',episode_record);self.completed.append(episode_record)
 def finish(self):
  self.phase='FINAL_ANALYSIS';c=self.controller;analysis=c.analysis_snapshot(reason='WORKED_RUNNER_FINAL')
  self.phase='ADMISSION_CONTEXT';context=self.ports.admission_context()
  if type(context) is not AdmissionContext:raise RunnerStopped('admission port must supply typed context')
  self.adapter=CPCAdapter.create(self.root/'admission',context,self.cfg.scope.run_ref+':admission')
  self.phase='ADMISSION'
  for item in self.raws:
   receipt=self.adapter.evaluate(item.raw,input_ref=item.input_ref)
   self.event('ADMISSION_RETURNED',{'input_ref':item.input_ref,'receipt_ref':receipt.receipt_ref,'status':receipt.status,'failure_code':receipt.failure_code,'disposition':None if receipt.result is None else receipt.result['disposition']})
  try:export=self.adapter.export();self.event('EXPORT_COMPLETED',export)
  except AdapterStopped:
   if self.adapter.view()['status']!='INCOMPLETE':raise
   self.event('EXPORT_REFUSED_UNRESOLVED',{'not_a_core_verdict':True})
  self.phase='COMMON_EVIDENCE'
  auxiliary={'source-response-recipe':self.ports.recipe.raw}
  native=capture_native(c,analysis)
  base_common=CommonEvidence(self.cfg.scope.run_ref+':common',tuple(self.raws),context,native,self.exposures,tuple(self.external),JoinPolicy.from_recipe(self.ports.recipe),auxiliary)
  remaining=64*1024*1024-base_common.receipt['aggregate_bytes']
  auxiliary=_collect_auxiliary(self.productions,auxiliary,remaining)
  common=CommonEvidence(self.cfg.scope.run_ref+':common',tuple(self.raws),context,native,self.exposures,tuple(self.external),JoinPolicy.from_recipe(self.ports.recipe),auxiliary)
  self.phase='BASELINES';comparison=run_comparison(common,cohort_ref=self.cfg.scope.run_ref+':cohort',snapshot_ref=self.cfg.scope.run_ref+':snapshot')
  _json(self.root/'comparison.json',comparison)
  _json(self.root/'common_receipt.json',common.receipt)
  self.phase='INVENTORIES'
  controls=tuple(SnapshotReference(c.store._store_ref,name,_sha(bytes.fromhex(raw)),len(bytes.fromhex(raw))) for name,raw in common.native['retained_local_snapshot_hex'].items())
  outcome_view=self.outcomes.view();outrefs={}
  for d in outcome_view['derivations']:
   for field in ['input_snapshots','output_snapshots']:
    for ref in d[field].values():outrefs[ref['snapshot_ref']]=SnapshotReference.from_mapping(ref)
  adapterrefs={}
  for record in self.adapter.journal.read_records():
   if record.payload['event']=='OPENED':
    ref=record.payload['data']['context_reference'];adapterrefs[ref['snapshot_ref']]=SnapshotReference.from_mapping(ref)
  adapter_view=self.adapter.view()
  for row in adapter_view['rows']:
   for field in ['raw_reference','returned_reference','requested_ref_reference']:
    ref=row.get(field)
    if ref is not None:adapterrefs[ref['snapshot_ref']]=SnapshotReference.from_mapping(ref)
  inventories=[capture_inventory(c.store,'CONTROLLER',controls),capture_inventory(self.outcomes.snapshots,'OUTCOME',tuple(outrefs.values())),capture_inventory(self.adapter.store,'ADAPTER',tuple(adapterrefs.values()))]
  inventories.extend(capture_producer_inventory(p.root,invocation_ref=p.invocation_ref,call_ref=p.call_ref) for p in self.productions)
  required={role:[i.store_ref for i in inventories if i.role==role] for role in ['CONTROLLER','OUTCOME','ADAPTER','PRODUCER']}
  self.phase='HANDOFF';report=build_handoff(common,comparison,outcome_view,report_ref=self.cfg.scope.run_ref+':handoff',inventories=tuple(inventories),required_stores=required,adapter_views={self.adapter.run_ref:adapter_view})
  _json(self.root/'handoff_report.json',report);_json(self.root/'outcome_view.json',outcome_view);_json(self.root/'controller_view.json',c.view());_json(self.root/'adapter_view.json',adapter_view);_json(self.root/'episode_ledger.json',self.completed)
  (self.root/'handoff').mkdir(mode=0o700)
  for mode in ['RESTRICTED','READER_CANDIDATE']:write_handoff(report,self.root/'handoff'/mode,mode=mode)
  self.phase='READONLY_REPLAY';replayed=OfflineController.open_readonly(c.root,c.scope,c.context)
  if canonical_json_bytes(replayed.view())!=canonical_json_bytes(c.view()):raise RunnerStopped('controller readonly replay differs')
  if canonical_json_bytes(OutcomeStore.open_readonly(self.outcomes.root,self.cfg.scope.run_ref).view())!=canonical_json_bytes(outcome_view):raise RunnerStopped('outcome readonly replay differs')
  verify_handoff(self.root/'handoff/RESTRICTED');verify_handoff(self.root/'handoff/READER_CANDIDATE',mode='READER_CANDIDATE')
  self.phase='COMPLETED'
  return RunnerResult(str(self.root),'COMPLETED' if report['status']=='RECONCILED_DECLARED_SCOPE' else 'DIAGNOSTIC_INCOMPLETE',self.phase,None,freeze_json(self.counts()),report['status'])
 def counts(self):
  result={'supplied_operations':self.operations,'observation_ingestions_attempted':self.observations,'producer_calls_returned':len(self.productions),'production_attempts':self.publications,'completed_episodes':len(self.completed),'complete_core_inputs':len(self.raws),'external_rows':len(self.external),'source_only_publications':sum(len(e['unsubmitted_exposures']) for e in self.completed)}
  if self.adapter is not None:
   try:result['core_inputs_submitted']=self.adapter.view()['received']
   except Exception:result['admission_unavailable']=True
  else:result['core_inputs_submitted']=0
  if self.controller is not None:
   try:
    state=self.controller.view();result['controller']=plain_json(state['counts'])
    linked={decode_json_object(raw)['payload']['invocation_id'] for raw in self.exposures.values()}
    published={p['invocation_ref'] for p in state['publications'].values()}
    result['source_only_publications']=len(published-linked)
    result['publication_uncertain']=sum(1 for row in state['invocations'].values() if row['publication_unresolved'])
   except Exception:result['controller_unavailable']=True
  result['retained_chains_not_submitted']=len(self.raws)-result.get('core_inputs_submitted',0)
  if self.outcomes is not None:
   try:result['outcome_derivations']=len(self.outcomes.view()['derivations'])
   except Exception:result['outcomes_unavailable']=True
  return result

def _seal_run(root):
 files={}
 for p in sorted(root.rglob('*')):
  meta=p.lstat()
  if stat.S_ISLNK(meta.st_mode) or not (stat.S_ISDIR(meta.st_mode) or stat.S_ISREG(meta.st_mode)):raise RunnerStopped('run output nonregular/symlink refused')
  if stat.S_ISREG(meta.st_mode) and meta.st_nlink!=1:raise RunnerStopped('run output hardlink refused')
  if stat.S_ISREG(meta.st_mode) and p!=root/'RUNNER_MANIFEST.json':files[str(p.relative_to(root))]={'sha256':_sha(p.read_bytes()),'bytes':meta.st_size}
 _json(root/'RUNNER_MANIFEST.json',{'format':'wss-worked-runner-manifest-v1','files':files})

def run_offline(root:str|Path,config:RunnerConfig,ports:RunnerPorts)->RunnerResult:
 """Complete local orchestration from explicitly supplied transports/signers.

 No IO adapters are imported from test names or user-named modules. External
 callbacks remain trusted declarations; source truth/scientific validity and
 rights cannot be certified here. No same-root retry or writable reopen exists.
 """
 if type(config) is not RunnerConfig or type(ports) is not RunnerPorts:raise ContractError('typed runner config/ports required')
 target=_real_directory(root,exists=False)
 with offline_guard():
  target.mkdir(mode=0o700);_fsync_directory(target.parent)
  for name in ['events','received','producers']:(target/name).mkdir(mode=0o700)
  state=_Run(target,config,ports)
  try:
   _json(target/'STARTED.json',{'format':'wss-worked-runner-start-v1','mode':'OFFLINE_SUPPLIED_EVIDENCE','evidence_class':config.evidence_class,'scope_purpose_semantics':'bookkeeping workflow label, not proof of source truth','scope':config.scope.to_mapping(),'configuration':config.to_mapping(),'authority':'SUPPLIED_DECLARATIONS_ONLY','release':'NOT_AUTHORIZED'})
   state.controller=OfflineController.create(target/'controller',config.scope,config.context)
   state.outcomes=OutcomeStore.create(target/'outcomes',config.scope.run_ref)
   for episode in config.episodes:state.episode(episode)
   result=state.finish()
  except Exception as exc:
   # Type only; never echo callback text, key material or arbitrary transport.
   failure={'format':'wss-worked-runner-failure-v1','phase':state.phase,'exception_type':type(exc).__name__,'counts':state.counts(),'no_retry':True,'existing_partial_roots_retained':True}
   try:_json(target/'RUNNER_FAILURE.json',failure)
   except Exception:pass
   result=RunnerResult(str(target),'FAILED',state.phase,type(exc).__name__,freeze_json(failure['counts']),None)
  # Keep terminal storage/serialization outside the pipeline handler. A failure
  # here is not a reason to rerun the pipeline or overwrite an existing result.
  _json(target/'RUNNER_RESULT.json',result.to_mapping());_seal_run(target)
  return result

def _read_checked(path,limit):
 fd=_checked_fd(path,os.O_RDONLY)
 with os.fdopen(fd,'rb') as stream:raw=stream.read(limit+1)
 if len(raw)>limit:raise ContractError('runner metadata byte bound exceeded')
 return raw

def verify_worked_output(root:str|Path)->Mapping:
 """Read-only manifest/result/delivery consistency. No execution or repair."""
 target=_real_directory(root,exists=True)
 manifest=decode_json_object(_read_checked(target/'RUNNER_MANIFEST.json',4*1024*1024))
 if set(manifest)!={'format','files'} or manifest['format']!='wss-worked-runner-manifest-v1':raise ContractError('runner manifest schema invalid')
 entries=list(target.rglob('*'))
 for path in entries:
  meta=path.lstat()
  if stat.S_ISLNK(meta.st_mode) or not (stat.S_ISDIR(meta.st_mode) or stat.S_ISREG(meta.st_mode)) or (stat.S_ISREG(meta.st_mode) and meta.st_nlink!=1):raise ContractError('runner output nonregular/link refused')
 observed={str(p.relative_to(target)) for p in entries if p.is_file() and p!=target/'RUNNER_MANIFEST.json'}
 if observed!=set(manifest['files']):raise ContractError('runner output inventory differs')
 for rel,e in manifest['files'].items():
  name=Path(rel)
  if name.is_absolute() or '..' in name.parts:raise ContractError('manifest path escapes root')
  p=target/name
  if p.is_symlink() or not p.is_file() or p.stat().st_size!=e['bytes'] or _sha(p.read_bytes())!=e['sha256']:raise ContractError('runner output bytes differ')
 result=decode_json_object(_read_checked(target/'RUNNER_RESULT.json',1048576))
 expected={'format','root','status','phase','error_type','counts','report_status','mode','native_or_provider_connector_used','scientific_or_release_approval'}
 if set(result)!=expected or result['format']!='wss-worked-runner-result-v1' or result['status'] not in {'FAILED','COMPLETED','DIAGNOSTIC_INCOMPLETE'}:raise ContractError('runner result schema invalid')
 if result['mode']!='OFFLINE_SUPPLIED_EVIDENCE' or result['native_or_provider_connector_used'] is not False or result['scientific_or_release_approval'] is not False:raise ContractError('runner result boundary flags invalid')
 if type(result['root']) is not str or not result['root'] or type(result['phase']) is not str or not result['phase'] or type(result['counts']) is not dict:raise ContractError('runner result scope/count types invalid')
 if result['status']=='FAILED':
  failure=decode_json_object(_read_checked(target/'RUNNER_FAILURE.json',1048576))
  if result['report_status'] is not None or type(result['error_type']) is not str or not result['error_type'] or failure.get('format')!='wss-worked-runner-failure-v1' or failure.get('phase')!=result['phase'] or failure.get('exception_type')!=result['error_type'] or failure.get('counts')!=result['counts'] or failure.get('no_retry') is not True:raise ContractError('runner failure/result invariants invalid')
 else:
  expected_report='RECONCILED_DECLARED_SCOPE' if result['status']=='COMPLETED' else 'DIAGNOSTIC_INCOMPLETE'
  if result['phase']!='COMPLETED' or result['error_type'] is not None or result['report_status']!=expected_report or (target/'RUNNER_FAILURE.json').exists():raise ContractError('runner success/result invariants invalid')
 if result['status']!='FAILED':
  report=decode_json_object(_read_checked(target/'handoff_report.json',64*1024*1024))
  if report['status']!=result['report_status']:raise ContractError('result/handoff status differs')
  for mode in ['RESTRICTED','READER_CANDIDATE']:verify_handoff(target/'handoff'/mode,mode=mode)
 return freeze_json({'format':'wss-worked-runner-verification-v1','status':'VERIFIED_LOCAL_BYTES','runner_status':result['status'],'files':len(observed),'scientific_or_release_approval':False})

def main(argv=None):
 import argparse
 parser=argparse.ArgumentParser(description='Offline worked runner: supplied typed ports via Python API, no native connector or dynamic plugins.')
 commands=parser.add_subparsers(dest='command',required=True)
 check=commands.add_parser('check-plan');check.add_argument('path')
 verify=commands.add_parser('verify-output');verify.add_argument('root')
 a=parser.parse_args(argv)
 if a.command=='check-plan':
  path=Path(a.path)
  fd=_checked_fd(path,os.O_RDONLY)
  with os.fdopen(fd,'rb') as stream:raw=stream.read(1048577)
  if len(raw)>1048576:raise ContractError('bounded regular plan required')
  cfg=RunnerConfig.from_bytes(raw);value={'plan_shape':'VALID','episodes':len(cfg.episodes),'max_operations':cfg.max_operations,'max_observations':cfg.max_observations,'max_publications':cfg.max_publications,'authorization_or_readiness':False}
 else:value=verify_worked_output(a.root)
 print(json.dumps(plain_json(value),ensure_ascii=False,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
