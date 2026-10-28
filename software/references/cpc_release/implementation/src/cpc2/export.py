"""Whitelisted export of SDK decisions, without outcome values/content or silent loss."""
from __future__ import annotations
import json
from pathlib import Path
from .schema import validate_named

EXPORT_FIELDS = {'input_ref','case_id','experiment_id','experiment_version','unit_token',
                 'attributed_condition','artifact_version','exposure_record_id','exposure_digest',
                 'outcome_key','purpose'}

def partition_results(results: list[dict]) -> dict:
    admitted, excluded, seen = [], [], set()
    counts = {'ADMIT':0,'REJECT':0,'QUARANTINE':0,'ERROR_INPUT':0,'NOT_EVALUATED_CONFIG':0}
    for result in results:
        if validate_named(result, 'result'):
            raise ValueError('unsupported result structure; export aborted before writing')
        ref = result['input_ref']
        if ref in seen:
            raise ValueError('duplicate operator input_ref; export aborted')
        seen.add(ref)
        disposition = result['disposition']
        if disposition == 'ADMIT':
            record = result['admitted_record']
            if not isinstance(record, dict) or set(record) != EXPORT_FIELDS or validate_named(record,'admitted_export'):
                raise ValueError('incomplete or non-whitelisted admitted record')
            if record['input_ref'] != ref or record['case_id'] != result['case_id']:
                raise ValueError('result/export identity mismatch')
            if any(d['disposition'] in {'REJECT','ERROR_INPUT','QUARANTINE','NOT_EVALUABLE','ERROR_CONFIG'} for d in result['diagnostics']):
                raise ValueError('ADMIT contradicts diagnostics')
            admitted.append(dict(record)); counts['ADMIT'] += 1
        else:
            if result['admitted_record'] is not None:
                raise ValueError('refused result cannot carry admitted export')
            ledger_status = 'NOT_EVALUATED_CONFIG' if disposition == 'ERROR_CONFIG' else disposition
            if ledger_status not in counts:
                raise ValueError('unknown disposition')
            excluded.append({'input_ref':ref,'input_sha256':result['input_sha256'],
                             'case_id':result['case_id'],'contract_version':result['contract_version'],
                             'profile_id':result['profile_id'],'profile_version':result['profile_version'],
                             'disposition':ledger_status,'diagnostics':result['diagnostics']})
            counts[ledger_status] += 1
    if len(results) != len(admitted) + len(excluded) or sum(counts.values()) != len(results):
        raise RuntimeError('export accounting invariant violated')
    return {'admitted':admitted,'excluded':excluded,'counts':counts,'received':len(results),
            'accounting_complete':True,'uniqueness_scope':'operator input_ref in this batch only'}

def export_results(results: list[dict], output: str | Path) -> dict:
    partition = partition_results(results)
    directory = Path(output)
    directory.mkdir(parents=True,exist_ok=False)
    for filename,rows in [('admitted.jsonl',partition['admitted']),('exclusion_ledger.jsonl',partition['excluded'])]:
        (directory/filename).write_text(''.join(json.dumps(row,sort_keys=True,ensure_ascii=False)+'\n' for row in rows),encoding='utf-8')
    summary = {k:v for k,v in partition.items() if k not in {'admitted','excluded'}}
    (directory/'accounting.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    return summary
