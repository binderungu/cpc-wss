"""Reader entrypoint: local artifact qualification, never a study/native runner."""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SOFTWARE = ROOT / 'software'
sys.dont_write_bytecode = True
sys.path[:0] = [str(SOFTWARE / 'src'), str(SOFTWARE / 'references/cpc_release/implementation/src')]

def deny_external(event, args):
    if event.startswith(('socket.', 'subprocess.', 'sqlite3.')) or event in {
        'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.exec'}:
        raise RuntimeError('Offline examples forbid external transport/process/database operations')

sys.addaudithook(deny_external)

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')

def check(condition, reason):
    if not condition:
        raise RuntimeError(reason)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    check(not out.exists() and out.parent.is_dir(), 'Unused output and existing parent required')
    # Never allow new output inside the package or a filesystem containing it.
    check(not out.is_relative_to(ROOT) and not ROOT.is_relative_to(out), 'Output must be outside package')
    out.mkdir(mode=0o700)
    summary = {'evidence_class': 'OFFLINE_RELEASE_ENGINEERING_QA', 'offline_only': True,
               'scientific_experiment': False, 'native_access': False, 'source_version': '1.12.0'}
    try:
        from cpc2.api import validate_raw
        from cpc2.export import export_results
        from wss_bridge.configuration import verify_pinned_references
        from wss_bridge.cpc_adapter import AdmissionContext, CPCAdapter
        from wss_bridge.controller import OfflineController, ControllerContext
        from wss_bridge.ledger import LedgerScope, SnapshotReference
        from wss_bridge.native_contract import SourceIdentity, ActorBinding, NativeTarget
        from wss_bridge.outcomes import OutcomeStore, OutcomeRecipe, external_from_outcome
        from wss_bridge.join import CoreEntry, JoinPolicy, mapping_from_analysis, analyze
        from wss_bridge.counterparts import read_verified_inputs, project_counterparts
        from wss_bridge.primitives import plain_json

        # Import every frozen Python module, never execute an entrypoint.
        imported = []
        for p in sorted((SOFTWARE / 'src/wss_bridge').glob('*.py')):
            name = 'wss_bridge' if p.stem == '__init__' else 'wss_bridge.' + p.stem
            importlib.import_module(name)
            imported.append(name)
        verify_pinned_references(SOFTWARE / 'references')
        summary['imported_modules'] = imported

        # U1 and U2: four existing synthetic D1 fixtures; no fixture fabrication.
        cases = read(ROOT / 'examples/core/CASES.json')
        context = read(ROOT / cases[0]['context'])
        keys = context['key_registry']
        check(all(v.startswith('SYNTHETIC_ONLY_') for v in keys.values()), 'Public synthetic keys only')
        results = []
        for i, case in enumerate(cases):
            ctx = read(ROOT / case['context'])
            raw = (ROOT / case['input']).read_bytes()
            check(hashlib.sha256(raw).hexdigest() == case['original_oracle']['input_sha256'], 'Fixture bytes changed')
            result = validate_raw(raw, ctx['profile'], ctx['key_registry'], ctx['validation_time'], input_ref=f'rc3-core-{i}')
            check(result['disposition'] == case['expected_disposition'], 'Core fixture verdict mismatch')
            results.append(result)
        write(out / 'core_results.json', results)
        exported = export_results(results, out / 'core_export')
        check(exported['received'] == 4 and exported['counts'] == {
            'ADMIT': 1, 'REJECT': 1, 'QUARANTINE': 1, 'ERROR_INPUT': 1, 'NOT_EVALUATED_CONFIG': 0}, 'Export accounting mismatch')
        summary['core_dispositions'] = [r['disposition'] for r in results]
        summary['core_export'] = exported

        # U3: new local retained adapter batch; original source/inputs untouched.
        admission = AdmissionContext(context['profile'], keys, context['validation_time'])
        adapter = CPCAdapter.create(out / 'adapter', admission, 'rc3-reader-adapter')
        for i, case in enumerate(cases):
            adapter.evaluate((ROOT / case['input']).read_bytes(), input_ref=f'rc3-adapter-{i}')
        adapter.export()
        view = plain_json(adapter.view())
        check(view['received'] == 4 and view['counts'] == exported['counts'], 'Adapter accounting mismatch')
        write(out / 'adapter_view.json', view)
        summary['adapter_received'] = view['received']

        # U4: derive in NEW store from exact retained read-only controller data.
        saved = ROOT / 'examples/retained_handoff/common/runner'
        terminal = read(saved / 'controller_view.json')
        ctx = dict(terminal['context'])
        for field, typ in [('source', SourceIdentity), ('actor', ActorBinding),
                           ('task_target', NativeTarget), ('followup_target', NativeTarget)]:
            ctx[field] = typ(**ctx[field])
        scope = LedgerScope(**read(saved / 'controller/journal/ledger.meta.json')['scope'])
        controller = OfflineController.open_readonly(saved / 'controller', scope, ControllerContext(**ctx))
        old_outcomes = read(saved / 'outcome_view.json')
        outcome_store = OutcomeStore.create(out / 'derived_outcomes', 'rc3-reader-outcomes')
        recipes, exposures, analysis_refs = {}, {}, {}
        derived = []
        for receipt, original in zip(old_outcomes['derivations'], old_outcomes['outcomes']):
            blobs = {}
            for label in ('exposure', 'recipe'):
                ref = receipt['input_snapshots'][label]
                name = hashlib.sha256(ref['snapshot_ref'].encode()).hexdigest() + '.bin'
                raw = (saved / 'outcomes/snapshots' / name).read_bytes()
                check('sha256:' + hashlib.sha256(raw).hexdigest() == ref['sha256'], 'Saved input digest mismatch')
                blobs[label] = raw
            recipe = OutcomeRecipe(blobs['recipe'])
            analysis_ref = SnapshotReference.from_mapping(receipt['analysis_reference'])
            item = plain_json(outcome_store.derive(controller, analysis_ref, blobs['exposure'], recipe, original['composite']['purpose']))
            check(item['lineage'] == original['lineage'] and item['value'] == original['value']
                  and item['measure_state'] == original['measure_state'], 'Selected-source semantics mismatch')
            token = original['composite']['unit_token']
            recipes[token], exposures[token], analysis_refs[token] = recipe, blobs['exposure'], analysis_ref
            derived.append(item)
        write(out / 'new_derived_outcomes.json', derived)
        check(len(derived) == 3, 'Three saved selections required')
        summary['selected_source_derivations'] = len(derived)
        summary['selected_source_semantics_match'] = True
        summary['outcome_ids'] = 'New random bookkeeping IDs; lineage/value/state compared, no original replacement'

        # U5: consume ORIGINAL retained core returns, not new outcome identities.
        comparison = read(saved / 'comparison.json')
        reference = comparison['arms']['CPC_REFERENCE']
        entries = [CoreEntry(ledger['receipt_ref'], row['input_ref'], row['result'])
                   for row, ledger in zip(reference['results'], reference['join']['core_ledger'])]
        mappings = {}
        for entry in entries:
            token = entry.result['admitted_record']['unit_token']
            mappings[entry.receipt_ref] = mapping_from_analysis(controller, analysis_refs[token], entry, exposures[token])
        policy = JoinPolicy.from_recipe(next(iter(recipes.values())))
        join = plain_json(analyze(entries, [external_from_outcome(v) for v in old_outcomes['outcomes']], mappings,
                                  policy, cohort_ref=reference['join']['cohort_ref'], snapshot_ref=reference['join']['snapshot_ref']))
        check(join['counts'] == reference['join']['counts'], 'Saved join counts differ')
        terminals = [r['primary_reason'] for r in join['core_ledger']]
        check(terminals == ['JOINED', 'JOINED', 'NATIVE_MAPPING_HOLD'], 'Join/HOLD mismatch')
        e3 = join['core_ledger'][2]
        check(e3['value'] is None and e3['admission_multiplicity'] == e3['external_multiplicity'] == 1, 'E3 accounting changed')
        write(out / 'join.json', join)
        summary['join_terminals'] = terminals
        summary['E3'] = {k: e3[k] for k in ('value', 'admission_multiplicity', 'external_multiplicity', 'reason_flags')}

        # U6: pure three-arm projection of retained results, no re-evaluation.
        inputs = read_verified_inputs(saved)
        projected = plain_json(project_counterparts(inputs['handoff_report'], inputs['terminal_controller_view'],
            inputs['episode_ledger'], producer_consumptions=inputs['producer_consumptions'], runner_start=inputs['runner_start']))
        write(out / 'counterparts.json', projected)
        summary['projection_arm_count'] = len(comparison['arms'])
        check(summary['projection_arm_count'] == 3, 'Three full-information arms required')
        summary['preserved_negative_results'] = {
            'D2': 'four ADMIT / primary JOINED / physical MISMATCH; no HMAC replay',
            'UF5': 'NO_ADDED_LA_HANDOFF_VALUE', 'JLA': 'STOP_CURRENT_JLA_FORMULATION',
            'Y_next': 'NOT_MEASURED / NOT_VALIDATED_HERE'}
        summary['status'] = 'PASS'
        write(out / 'RESULT.json', summary)
        print(json.dumps(summary))
    except Exception as exc:
        summary.update(status='FAIL', exception_type=type(exc).__name__, message=str(exc))
        write(out / 'FAILURE.json', summary)
        raise

if __name__ == '__main__':
    main()
