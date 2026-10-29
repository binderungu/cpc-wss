"""Independent full-information CPC 2.0.1 rules comparator; no CPC imports."""
from __future__ import annotations
COMPARATOR_VERSION = "1.0.1"
import hashlib
import hmac
import json
from pathlib import Path
import re
from datetime import datetime, timezone

SPEC = Path(__file__).resolve().parents[1] / 'implementation' / 'spec'
FIELDS = json.loads((SPEC / 'FIELD_REQUIREMENTS.json').read_text())
HASH = re.compile(r'sha256:[0-9a-f]{64}\Z')
MAC = re.compile(r'hmac-sha256:[0-9a-f]{64}\Z')
RFC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z')
TYPES = ('assignment', 'resolution', 'exposure', 'outcome')
PROOFS = ('launch_attestation', 'commitment', 'usage_attestation', 'release_attestation')


def identifier(v, limit=256):
    return isinstance(v, str) and 0 < len(v) <= limit and v == v.strip() and not any(ord(c)<32 or 127<=ord(c)<160 for c in v)


def instant(v):
    if not isinstance(v, str) or not RFC.fullmatch(v):
        raise ValueError('timestamp format')
    dt = datetime.fromisoformat(v.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timezone absent')
    return dt.astimezone(timezone.utc)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical(value)).hexdigest()


def depth(v):
    if isinstance(v, dict):
        return max([0] + [1 for _ in v] + [1+depth(x) for x in v.values()])
    if isinstance(v, list):
        return max([0] + [1+depth(x) for x in v])
    return 0


def strict_decode(raw):
    def pairs(items):
        d = {}
        for k,v in items:
            if k in d:
                raise ValueError('duplicate key')
            d[k] = v
        return d
    def no_number(_):
        raise ValueError('unsupported noninteger number')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_float=no_number, parse_constant=no_number)


class Rules:
    def __init__(self, profile, keys, now):
        self.p, self.keys, self.now = profile, keys, now
        self.diagnostics = []
        self.proof_ids = set()
        self.limit = profile['input_limits']['max_identifier_chars']

    def add(self, rule, code, path, disp='REJECT'):
        d = dict(rule_id=rule, code=code, path=path, disposition=disp)
        if d not in self.diagnostics:
            self.diagnostics.append(d)

    def shape(self, obj, required, path, optional=(), special=None):
        special = special or {}
        if not isinstance(obj, dict):
            self.add('I02','OBJECT_REQUIRED',path,'ERROR_INPUT')
            return False
        before = len(self.diagnostics)
        for key in set(obj) - set(required) - set(optional):
            self.add('I03','UNKNOWN_FIELD',path+'.'+key,'ERROR_INPUT')
        for key in required:
            v = obj.get(key)
            ok = special[key](v) if key in special else identifier(v, self.limit)
            if not ok:
                self.add('I02','REQUIRED_FIELD_SHAPE',path+'.'+key,'ERROR_INPUT')
        if 'extensions' in obj:
            ex = obj['extensions']
            if not isinstance(ex,dict):
                self.add('I02','EXTENSIONS_OBJECT',path+'.extensions','ERROR_INPUT')
            else:
                for key in ex:
                    if key not in self.p['extension_keys']:
                        self.add('I03','UNREGISTERED_EXTENSION',path+'.extensions.'+key,'ERROR_INPUT')
        return len(self.diagnostics) == before

    def stamp(self, obj, path):
        try:
            start, issued, end = [instant(obj[k]) for k in ('valid_from','issued_at','expires_at')]
        except (KeyError,ValueError,TypeError,OverflowError):
            self.add('I02','TIMESTAMP_SHAPE',path,'ERROR_INPUT')
            return None
        if not (start <= issued < end and issued <= self.now and start <= self.now < end):
            self.add('R06','FRESHNESS_INTERVAL',path)
        return issued

    def integrity(self, obj, signed, issuer, path):
        seal = obj.get('integrity')
        if not self.shape(seal, FIELDS['integrity_required'], path+'.integrity'):
            return False
        if not HASH.fullmatch(seal['content_digest']) or not MAC.fullmatch(seal['mac']) or not seal['key_id'].isascii():
            self.add('I02','INTEGRITY_ENCODING',path+'.integrity','ERROR_INPUT')
            return False
        good = True
        expected = self.p['issuer_key_policy'].get(issuer)
        key = self.keys.get(seal['key_id'])
        if seal['algorithm'] != 'HMAC-SHA256' or seal['key_id'] != expected or not isinstance(key,str):
            self.add('R01','KEY_ROLE_OR_ALGORITHM',path+'.integrity')
            good = False
        actual = digest(signed)
        if actual != seal['content_digest']:
            self.add('R01','CONTENT_DIGEST',path+'.integrity.content_digest')
            good = False
        if isinstance(key,str):
            mac = 'hmac-sha256:'+hmac.new(key.encode('utf-8'), seal['content_digest'].encode('ascii'),hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac,seal['mac']):
                self.add('R01','MAC',path+'.integrity.mac')
                good = False
        return good

    def context(self, obj, parent, issuer, path, record=False):
        expected = {k:self.p[k] for k in ('contract_version','profile_id','profile_version','experiment_id','experiment_version','deployment_id','context_id')}
        expected['audience'] = self.p['expected_audience']
        expected['issuer'] = issuer
        if record:
            expected['schema_version'] = self.p['schema_version']
        else:
            expected['unit_token'] = parent.get('unit_token')
        for key,wanted in expected.items():
            if key in obj and obj[key] is not None and wanted is not None and obj[key] != wanted:
                self.add('R01','EXTERNAL_CONTEXT',path+'.'+key)

    def proof(self, obj, name, parent, path):
        if not self.shape(obj, ('body','integrity'), path, special={'body':lambda x:isinstance(x,dict),'integrity':lambda x:isinstance(x,dict)}):
            return None
        body = obj['body']
        special = {k:lambda x:isinstance(x,dict) for k in ('namespace_values','artifacts','usage_attestation','measured_components')}
        special['sequence'] = lambda x:type(x) is int and x>=0
        self.shape(body, FIELDS['proof_body_required'][name], path+'.body', ('extensions',), special)
        self.context(body, parent, self.p['proof_issuers'][name], path+'.body')
        self.stamp(body, path+'.body')
        pid = body.get('proof_id')
        if identifier(pid):
            if pid in self.proof_ids:
                self.add('R08','DUPLICATE_PROOF_ID',path+'.body.proof_id')
            self.proof_ids.add(pid)
        valid = self.integrity(obj,body,body.get('issuer'),path)
        if name in ('commitment','usage_attestation','release_attestation') and identifier(body.get('clock_id')) and body['clock_id'] != self.p['observer_clock_id']:
            self.add('R07','UNTRUSTED_CLOCK',path+'.body.clock_id')
        return body if valid else None

    def equal(self, a,b,rule,path,code):
        if a is not None and b is not None and a != b:
            self.add(rule,code,path)

    def relation(self, obj, predecessor, prefix, path, rule='R07'):
        if predecessor is not None:
            self.equal(obj.get(prefix+'_record_id'),predecessor.get('record_id'),rule,path+'.'+prefix+'_record_id','RECORD_REFERENCE')
            self.equal(obj.get(prefix+'_digest'),predecessor.get('integrity',{}).get('content_digest'),rule,path+'.'+prefix+'_digest','DIGEST_REFERENCE')

    def artifacts(self, vector, bundle, path):
        registry = self.p['artifact_registry'].get(bundle)
        if registry is None:
            self.add('R05','UNREGISTERED_BUNDLE',path)
            return
        if not isinstance(vector,dict):
            return
        for key in set(vector)^set(registry):
            self.add('I02' if key in registry else 'I03','COMPONENT_SET',path+'.'+key,'ERROR_INPUT')
        for key,item in vector.items():
            if not self.shape(item,FIELDS['artifact_entry_required'],path+'.'+key):
                continue
            if not HASH.fullmatch(item['digest']):
                self.add('I02','DIGEST_ENCODING',path+'.'+key+'.digest','ERROR_INPUT')
            if key in registry and item != registry[key]:
                self.add('R05','REGISTRY_VECTOR',path+'.'+key)
            if key in self.p['required_measured_components'] and item['evidence_mode'] != 'measured':
                self.add('R05','MEASURED_REQUIRED',path+'.'+key+'.evidence_mode')

    def namespaces(self, ns, condition, path):
        if not isinstance(ns,dict) or not ns:
            self.add('I02','NAMESPACE_OBJECT',path,'ERROR_INPUT')
            return
        policy = self.p['namespace_policy']
        for key,rule in policy.items():
            if rule['required'] and key not in ns:
                self.add('I02','REQUIRED_NAMESPACE',path+'.'+key,'ERROR_INPUT')
        for key,value in ns.items():
            if not identifier(value,self.limit):
                self.add('I02','NAMESPACE_VALUE',path+'.'+key,'ERROR_INPUT')
            elif key not in policy:
                self.add('R03','UNAUTHORIZED_NAMESPACE',path+'.'+key)
            elif policy[key]['role'] != 'descriptive':
                mapped = policy[key]['mapping'].get(value)
                if mapped is None or mapped != condition:
                    self.add('R03','RAW_CONDITION_MAPPING',path+'.'+key)

    def records(self, chain):
        groups = {t:[] for t in TYPES}
        ids, nonces = set(),set()
        supported = []
        for i,r in enumerate(chain['records']):
            path = '$.records['+str(i)+']'
            if not isinstance(r,dict):
                self.add('I01','RECORD_OBJECT',path,'ERROR_INPUT'); continue
            typ = r.get('record_type')
            if typ not in TYPES:
                self.add('I03','UNKNOWN_RECORD_TYPE',path+'.record_type','ERROR_INPUT'); continue
            groups[typ].append((r,path))
            special = {'payload':lambda x:isinstance(x,dict),'integrity':lambda x:isinstance(x,dict), 'predecessor_record_id':lambda x:x is None if typ=='assignment' else identifier(x,self.limit),'predecessor_digest':lambda x:x is None if typ=='assignment' else isinstance(x,str) and HASH.fullmatch(x) is not None}
            self.shape(r,FIELDS['record_required'],path,('extensions',),special)
            self.context(r,None,self.p['record_issuers'][typ],path,True)
            for k in ('contract_version','profile_id','profile_version'):
                self.equal(r.get(k),chain.get(k),'R01',path+'.'+k,'CHAIN_ROUTE_CONTEXT')
            self.stamp(r,path)
            for k,seen in [('record_id',ids),('nonce',nonces)]:
                v = r.get(k)
                if identifier(v):
                    if v in seen:self.add('R08','DUPLICATE_'+k.upper(),path+'.'+k)
                    seen.add(v)
            payload = r.get('payload')
            pspecial = {k:lambda x:isinstance(x,dict) for k in ('claim_namespaces','launch_attestation','artifacts','commitment','release_attestation')}
            pspecial.update({k:lambda x:type(x) is bool for k in ('fallback_used','fallback_authorized','eligible')})
            pspecial['authorization_ref'] = lambda x:x is None or identifier(x,self.limit)
            self.shape(payload,FIELDS['payload_required'][typ],path+'.payload',special=pspecial)
            if self.integrity(r,{k:v for k,v in r.items() if k!='integrity'},r.get('issuer'),path):
                supported.append((r,path))
        for typ,values in groups.items():
            if len(values)==0:self.add('Q01','ABSENT_'+typ.upper(),'$.records','QUARANTINE')
            elif len(values)>1:self.add('Q02' if typ=='outcome' else 'R08','MULTIPLE_'+typ.upper(),'$.records','QUARANTINE' if typ=='outcome' else 'REJECT')
        # Never select among ambiguous record classes, nor treat invalid seals as trusted dependencies.
        trusted = {t:next((r for r,path in supported if r['record_type']==t),None) if len(groups[t])==1 else None for t in TYPES}
        a,r,e,o = [trusted[t] for t in TYPES]
        for rec,path in supported:
            if a:
                self.equal(rec.get('unit_token'),a.get('unit_token'),'R07',path+'.unit_token','UNIT_BINDING')
            previous = {'resolution':a,'exposure':r,'outcome':e}.get(rec['record_type'])
            if previous:
                self.equal(rec.get('predecessor_record_id'),previous.get('record_id'),'R07',path+'.predecessor_record_id','PREDECESSOR_ID')
                self.equal(rec.get('predecessor_digest'),previous.get('integrity',{}).get('content_digest'),'R07',path+'.predecessor_digest','PREDECESSOR_DIGEST')
                self.ordered(previous.get('issued_at'),rec.get('issued_at'),'R07',path+'.issued_at','ENVELOPE_ORDER')
        ap = a.get('payload',{}) if a else {}
        rp = r.get('payload',{}) if r else {}
        ep = e.get('payload',{}) if e else {}
        op = o.get('payload',{}) if o else {}
        if a and isinstance(ap,dict):
            for key,pkey in [('assigned_condition','conditions'),('assignment_policy_version','assignment_policy_version'),('scope','scope')]:
                v = ap.get(key)
                if identifier(v) and (v not in self.p[pkey] if isinstance(self.p[pkey],list) else v != self.p[pkey]):
                    self.add('R02','ASSIGNMENT_POLICY','assignment.payload.'+key)
            if identifier(ap.get('resource_id')) and self.p['resource_condition_map'].get(ap['resource_id']) != ap.get('assigned_condition'):
                self.add('R02','RESOURCE_CONDITION','assignment.payload.resource_id')
        conditions = []
        for payload,key in [(ap,'assigned_condition'),(rp,'requested_condition'),(rp,'resolved_condition'),(ep,'enacted_condition'),(op,'attributed_condition')]:
            if isinstance(payload,dict) and identifier(payload.get(key)):
                conditions.append(payload[key])
                if payload[key] not in self.p['conditions']:self.add('R02','CONDITION_DOMAIN',key)
        if len(set(conditions))>1:self.add('R02','LAYER_CONDITION_CONFLICT','$.records')
        launch = None
        if r and isinstance(rp,dict):
            self.equal(rp.get('resolver_version'),self.p['resolver_version'],'R02','resolution.payload.resolver_version','RESOLVER_VERSION')
            self.namespaces(rp.get('claim_namespaces'),rp.get('requested_condition'),'resolution.payload.claim_namespaces')
            launch = self.proof(rp.get('launch_attestation'),'launch_attestation',r,'resolution.payload.launch_attestation')
            if launch:
                self.relation(launch,a,'assignment','launch_attestation.body','R04')
                self.equal(launch.get('resource_id'),ap.get('resource_id'),'R04','launch_attestation.body.resource_id','LAUNCH_RESOURCE')
                self.equal(launch.get('launch_nonce'),ap.get('launch_nonce'),'R04','launch_attestation.body.launch_nonce','ASSIGNMENT_LAUNCH_NONCE')
                self.equal(launch.get('launch_nonce'),rp.get('launch_nonce'),'R04','resolution.payload.launch_nonce','RESOLUTION_LAUNCH_NONCE')
                self.equal(launch.get('namespace_values'),rp.get('claim_namespaces'),'R04','resolution.payload.claim_namespaces','ATTESTED_NAMESPACES')
                self.namespaces(launch.get('namespace_values'),rp.get('requested_condition'),'launch_attestation.body.namespace_values')
                if a:self.ordered(a.get('issued_at'),launch.get('issued_at'),'R04','launch_attestation.body.issued_at','LAUNCH_AFTER_ASSIGNMENT')
                self.ordered(launch.get('issued_at'),r.get('issued_at'),'R04','resolution.issued_at','LAUNCH_BEFORE_RESOLUTION')
            if rp.get('fallback_used') is False:
                if rp.get('fallback_authorized') is not False or rp.get('authorization_ref') is not None:self.add('R06','FALSE_FALLBACK_CONFLICT','resolution.payload')
            elif rp.get('fallback_used') is True:
                permission = self.p['fallback_permissions'].get(rp.get('authorization_ref'))
                if rp.get('fallback_authorized') is not True or not permission or permission['condition'] != rp.get('resolved_condition') or (e and ep.get('artifact_version') not in permission['artifact_versions']):
                    self.add('R06','FALLBACK_PERMISSION','resolution.payload')
        commit = usage = release = None
        if e and isinstance(ep,dict):
            self.artifacts(ep.get('artifacts'),ep.get('artifact_version'),'exposure.payload.artifacts')
            commit = self.proof(ep.get('commitment'),'commitment',e,'exposure.payload.commitment')
            release = self.proof(ep.get('release_attestation'),'release_attestation',e,'exposure.payload.release_attestation')
            if commit:
                self.relation(commit,r,'resolution','commitment.body','R05')
                for key in ('invocation_id','enacted_condition','artifact_version','artifacts'):
                    self.equal(commit.get(key),ep.get(key),'R05','commitment.body.'+key,'COMMIT_EXPOSURE_BINDING')
                self.artifacts(commit.get('artifacts'),commit.get('artifact_version'),'commitment.body.artifacts')
                usage = self.proof(commit.get('usage_attestation'),'usage_attestation',e,'commitment.body.usage_attestation')
            if usage:
                self.relation(usage,r,'resolution','usage_attestation.body','R05')
                self.equal(usage.get('invocation_id'),ep.get('invocation_id'),'R05','usage_attestation.body.invocation_id','USAGE_INVOCATION')
                measured = usage.get('measured_components')
                required = set(self.p['required_measured_components'])
                if isinstance(measured,dict):
                    for key in set(measured)^required:self.add('I02' if key in required else 'I03','MEASUREMENT_COMPONENT_SET','usage_attestation.body.measured_components.'+key,'ERROR_INPUT')
                    for key,item in measured.items():
                        path='usage_attestation.body.measured_components.'+key
                        if not self.shape(item,FIELDS['measured_component_required'],path):continue
                        if not HASH.fullmatch(item['digest']):self.add('I02','MEASUREMENT_DIGEST_ENCODING',path+'.digest','ERROR_INPUT')
                        self.equal(item['component_id'],key,'R05',path+'.component_id','COMPONENT_ID')
                        vector = ep.get('artifacts',{}).get(key,{})
                        for field in ('version','digest'):self.equal(item.get(field),vector.get(field),'R05',path+'.'+field,'MEASURED_VECTOR_BINDING')
                if r:self.ordered(r.get('issued_at'),usage.get('issued_at'),'R07','usage_attestation.body.issued_at','USE_AFTER_RESOLUTION')
            if release:
                self.equal(release.get('invocation_id'),ep.get('invocation_id'),'R05','release_attestation.body.invocation_id','RELEASE_INVOCATION')
                self.equal(release.get('exposure_record_id'),e.get('record_id'),'R07','release_attestation.body.exposure_record_id','RELEASE_EXPOSURE')
                self.equal(release.get('release_boundary'),self.p['release_boundary'],'R07','release_attestation.body.release_boundary','RELEASE_BOUNDARY')
                if commit:self.equal(release.get('commitment_digest'),digest(ep['commitment']),'R07','release_attestation.body.commitment_digest','IMMUTABLE_COMMITMENT')
                self.ordered(release.get('issued_at'),e.get('issued_at'),'R07','exposure.issued_at','RELEASE_BEFORE_FINAL_EXPOSURE')
            if usage and commit:self.ordered(usage.get('issued_at'),commit.get('issued_at'),'R07','commitment.body.issued_at','USE_BEFORE_COMMIT')
            if commit and release:self.ordered(commit.get('issued_at'),release.get('issued_at'),'R07','release_attestation.body.issued_at','COMMIT_BEFORE_RELEASE',strict=True)
            if usage and commit and release:
                sequences=[x.get('sequence') for x in (usage,commit,release)]
                if all(type(x) is int and x>=0 for x in sequences) and not sequences[0]<=sequences[1]<sequences[2]:self.add('R07','OBSERVED_SEQUENCE_ORDER','exposure.payload')
        if o and isinstance(op,dict):
            self.relation(op,e,'exposure','outcome.payload')
            for key,pkey in [('consent_authority_ref','consent_authority_refs'),('consent_policy_version','consent_policy_version'),('purpose','permitted_purposes')]:
                v=op.get(key)
                if identifier(v) and (v not in self.p[pkey] if isinstance(self.p[pkey],list) else v != self.p[pkey]):self.add('R06','CONSENT_OR_PURPOSE','outcome.payload.'+key)
            if op.get('consent_state') != 'consented' or op.get('eligible') is not True:self.add('R06','CONSENT_ELIGIBILITY','outcome.payload')
            try:instant(op.get('consent_at'))
            except (ValueError,TypeError,OverflowError):self.add('I02','CONSENT_TIMESTAMP','outcome.payload.consent_at','ERROR_INPUT')
            if usage:self.ordered(op.get('consent_at'),usage.get('issued_at'),'R06','outcome.payload.consent_at','PROSPECTIVE_CONSENT')
        return e,o

    def ordered(self, earlier,later,rule,path,code,strict=False):
        try:a,b=instant(earlier),instant(later)
        except (TypeError,ValueError,OverflowError):return
        if not (a<b if strict else a<=b):self.add(rule,code,path)


def config_errors(profile, keys, validation_time):
    try:
        instant(validation_time)
        required = ('profile_id','profile_version','contract_version','schema_version','experiment_id','experiment_version','expected_audience','deployment_id','context_id','scope','assignment_policy_version','resolver_version','mapping_version','consent_policy_version','observer_clock_id','release_boundary','profile_state','freeze_timestamp','conditions','resource_condition_map','namespace_policy','record_issuers','proof_issuers','issuer_key_policy','permitted_purposes','consent_authority_refs','artifact_registry','required_measured_components','component_canonicalizations','fallback_permissions','extension_keys','privacy_denylist','input_limits')
        if not isinstance(profile,dict) or set(profile)!=set(required):return True
        if profile['contract_version']!='2.0.1' or profile['schema_version']!='cpc-2.0.1' or profile['profile_state']!='frozen':return True
        # Scalar fields are explicit: conditions is a list, not an identifier.
        # Version 1.0.0 incorrectly inferred types from required-field positions.
        scalar_identifiers = ('profile_id', 'profile_version', 'contract_version',
            'schema_version', 'experiment_id', 'experiment_version',
            'expected_audience', 'deployment_id', 'context_id', 'scope',
            'assignment_policy_version', 'resolver_version', 'mapping_version',
            'consent_policy_version', 'observer_clock_id', 'release_boundary',
            'profile_state')
        for k in scalar_identifiers:
            if not identifier(profile[k]):return True
        instant(profile['freeze_timestamp'])
        limits=profile['input_limits']
        maximum={'max_bytes':1048576,'max_depth':32,'max_records':16,'max_identifier_chars':256}
        if set(limits)!=set(maximum) or any(type(limits[k]) is not int or not 1<=limits[k]<=v for k,v in maximum.items()):return True
        for k in ('conditions','permitted_purposes','consent_authority_refs','required_measured_components'):
            if not isinstance(profile[k],list) or not profile[k] or any(not identifier(x) for x in profile[k]) or len(set(profile[k]))!=len(profile[k]):return True
        if not isinstance(keys,dict):return True
        if set(profile['record_issuers'])!=set(TYPES) or set(profile['proof_issuers'])!=set(PROOFS):return True
        issuers=list(profile['record_issuers'].values())+list(profile['proof_issuers'].values())
        if any(not identifier(x) or x not in profile['issuer_key_policy'] for x in issuers):return True
        if any(not identifier(k) or not k.isascii() or not isinstance(keys.get(k),str) or not keys[k] for k in profile['issuer_key_policy'].values()):return True
        if profile['issuer_key_policy'][profile['proof_issuers']['commitment']]==profile['issuer_key_policy'][profile['proof_issuers']['usage_attestation']]:return True
        if not profile['artifact_registry'] or not profile['resource_condition_map'] or any(c not in profile['conditions'] for c in profile['resource_condition_map'].values()):return True
        components=None
        for vector in profile['artifact_registry'].values():
            if not isinstance(vector,dict) or not vector:return True
            if components is not None and set(vector)!=components:return True
            components=set(vector)
            for component,item in vector.items():
                if set(item)!=set(FIELDS['artifact_entry_required']) or not identifier(item['version']) or not HASH.fullmatch(item['digest']):return True
                if item['evidence_mode']!=('measured' if component in profile['required_measured_components'] else 'declared'):return True
        if not set(profile['required_measured_components'])<=components:return True
        if not isinstance(profile['namespace_policy'],dict) or not profile['namespace_policy']:return True
        authoritative=False
        for rule in profile['namespace_policy'].values():
            if set(rule)!= {'role','required','mapping'} or type(rule['required']) is not bool or rule['role'] not in ('authoritative','consistency','descriptive') or not isinstance(rule['mapping'],dict):return True
            if rule['role']!='descriptive' and (not rule['required'] or not rule['mapping'] or any(c not in profile['conditions'] for c in rule['mapping'].values())):return True
            authoritative |= rule['role']=='authoritative' and rule['required']
        if not authoritative:return True
        return False
    except (KeyError,ValueError,TypeError,AttributeError,OverflowError):return True


def validate_raw(raw, profile, key_registry, validation_time, *, input_ref):
    if isinstance(raw,str):raw=raw.encode('utf-8')
    if not isinstance(raw,bytes):raise TypeError('raw must be bytes or UTF-8 string')
    out={'input_ref':input_ref,'input_sha256':'sha256:'+hashlib.sha256(raw).hexdigest(),'case_id':None,'contract_version':None,'profile_id':None,'profile_version':None,'disposition':None,'diagnostics':[],'admitted_record':None}
    if config_errors(profile,key_registry,validation_time) or not identifier(input_ref):
        out.update(disposition='ERROR_CONFIG',diagnostics=[dict(rule_id='C01',code='INVALID_EXTERNAL_CONFIGURATION',path='$operator',disposition='ERROR_CONFIG')]);return out
    rules=Rules(profile,key_registry,instant(validation_time))
    try:
        if len(raw)>profile['input_limits']['max_bytes']:raise ValueError('byte limit')
        chain=strict_decode(raw)
        if depth(chain)>profile['input_limits']['max_depth'] or not isinstance(chain,dict):raise ValueError('depth/root')
        if not isinstance(chain.get('records'),list) or len(chain['records'])>profile['input_limits']['max_records']:raise ValueError('records/limit')
    except (ValueError,UnicodeError,RecursionError,OverflowError):
        out.update(disposition='ERROR_INPUT',diagnostics=[dict(rule_id='I01',code='UNSUPPORTED_WIRE',path='$',disposition='ERROR_INPUT')]);return out
    for k in ('case_id','contract_version','profile_id','profile_version'):out[k]=chain.get(k)
    rules.shape(chain,FIELDS['chain_required'],'$',special={'records':lambda x:isinstance(x,list)})
    for k in ('contract_version','profile_id','profile_version'):
        rules.equal(chain.get(k),profile[k],'R01','$.'+k,'ROOT_PROFILE')
    def privacy(v,path):
        if isinstance(v,dict):
            for k,val in v.items():
                if re.sub('[^a-z0-9]','',k.lower()) in profile['privacy_denylist']:rules.add('R06','PRIVACY_FORBIDDEN_FIELD',path+'.'+k)
                privacy(val,path+'.'+k)
        elif isinstance(v,list):
            for i,val in enumerate(v):privacy(val,path+'['+str(i)+']')
    privacy(chain,'$')
    exposure,outcome=rules.records(chain)
    precedence={'ADMIT':0,'QUARANTINE':1,'ERROR_INPUT':2,'REJECT':3}
    disposition=max([d['disposition'] for d in rules.diagnostics],key=precedence.get,default='ADMIT')
    out.update(disposition=disposition,diagnostics=rules.diagnostics)
    if disposition=='ADMIT':
        # Complete record set is established by the Q01/cardinality checks above.
        ep,op=exposure['payload'],outcome['payload']
        out['admitted_record']={'input_ref':input_ref,'case_id':chain['case_id'],'experiment_id':exposure['experiment_id'],'experiment_version':exposure['experiment_version'],'unit_token':exposure['unit_token'],'attributed_condition':op['attributed_condition'],'artifact_version':ep['artifact_version'],'exposure_record_id':exposure['record_id'],'exposure_digest':exposure['integrity']['content_digest'],'outcome_key':op['outcome_key'],'purpose':op['purpose']}
    return out
