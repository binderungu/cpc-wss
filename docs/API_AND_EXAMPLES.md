# Users, inputs, API and outputs

| Job | API | Supplied input | Example output / limitation |
|---|---|---|---|
| U1 developer | cpc2.api.validate_raw | raw bytes, separate profile/key registry/time | core_results.json; synthetic trust context, not physical-use truth |
| U2 steward | cpc2.export.export_results | actual supported core results | core_export/, 1 admitted + 3 excluded; scalar not exported |
| U3 integrator | CPCAdapter.create/evaluate/export/view | same four raw inputs/context, unused local root | adapter/, 4 retained receipts, export accounting; new IDs |
| U4 analyst | OutcomeStore.derive/external_from_outcome | read-only saved controller/prefix, exposure, frozen recipe/purpose | derived_outcomes/, score and source-key equality; new IDs, no learner observation |
| U5 analyst | mapping_from_analysis and analyze | saved prefix, retained core results, all external rows, policy | join.json, ADMIT vs JOINED/HOLD separate; E3 1/1 multiplicity |
| U6 steward/auditor | read_verified_inputs and project_counterparts | saved report, terminal controller, episode ledger, common inventory | counterparts.json, fixed three-arm shared projections |

All examples run in one process with network/subprocess/sqlite audit denials.
New files go only under the explicitly unused output root. Saved inputs are
opened read-only. Exact original records remain present beside new outputs.
The recipe and synthetic trust context are supplied explicitly. No historical
signing keys are used to revalidate native chains; U5 consumes retained results.
Only four D1 demonstration fixtures are evaluated anew; this is packaging QA,
not a repeated D1 campaign or new experiment. D2 HMAC is never replayed.

The complete source also includes reporting.build_handoff (typed CommonEvidence,
comparison, outcome view, inventories and adapter views), producer, controller
and native adapter modules. This release check does not invoke a full producer/
worked run, live native helper, or regenerate the scientific comparison arms.
Historical reporting and full-run evidence remains in the preserved handoff.

Expected RESULT fields: core_dispositions in fixed case order; core_export counts;
adapter_received=4; selected_source_derivations=3; selected_source_semantics_match;
join_terminals=[JOINED,JOINED,NATIVE_MAPPING_HOLD]; E3 value null and 1/1 multiplicity;
projection_arm_count=3; offline_only=true; status=PASS. Full result IDs are not
an expected byte-stable output. A failure must retain its output and process log.
