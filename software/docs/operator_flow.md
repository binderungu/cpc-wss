# WP09 offline operator flow and handoff

This is the generic reporting path for WSS V2 N7–N9/U1–U6 and WP09/Q03/Q10.
It reads supplied local evidence only. No Moodle/LIRA/PHP helper, DB/provider,
native checkpoint, experiment, learner study or manuscript path is executed.

## Inputs and pure reconstruction

1. Use the exact frozen `CommonEvidence` and actual `run_comparison` outputs from
   a declared cohort/snapshot. The caller obtains them under the separately
   authorized offline workflow. The reporter never invokes the core, comparator
   or producer. B0/B2 keep full common information; their shared engine/capture/
   mapping/join dependencies remain explicit. B1 remains an ablation that abstains.
2. Supply a saved `OutcomeStore.view()` and, if relevant, separately named adapter
   batch views. A separate adapter batch may overlap comparison raw inputs; do
   not add its received count to the comparison denominator. Missing/partial
   data is not zero or a fake core verdict.
3. Declare required SnapshotStore IDs for CONTROLLER/PRODUCER/OUTCOME/ADAPTER.
   Explicitly call `capture_inventory(store, role, references)` for each root.
   It checks local metadata, visits only the flat declared snapshot directory,
   hashes bounded regular payloads and lists nonregular/unreadable/missing refs.
   It does not follow links/FIFOs or discover references inside ordinary payloads.
   Caller references must be typed; known capture manifests are expanded by the
   builder only through their typed raw/blob fields already retained in common
   evidence. Unknown orphans remain visible. Missing inventories/reference
   coverage prevent complete declared-root status. Inventories are point-in-time
   cooperative receipts, not a cross-store transaction or hostile-process proof.
4. `build_handoff(common, comparison, outcome_view, report_ref=..., inventories=...,
   required_stores=..., adapter_views=...)` is pure. It replays the native event
   prefix, reconstructs each arm's join and denominator from supplied actual
   dispositions, checks comparison/B1 outputs, and recomputes outcome and separate
   adapter partitions. It never changes a core verdict, invents a new outcome,
   chooses a later score-valid response or refreshes a historical snapshot.

Native opportunities/operations/ingestions/occurrences/attempts/invocations/
publications/follow-ups/analysis history, derivations/external rows, per-arm
core/mapping/join buckets, source-only attempts, and per-store orphans are separate
grains. Prefix analysis history excludes its own analysis event; the current
captured analysis and head are separate scope fields. Duplicate ingestions do
not become additional occurrences. Failed/uncertain calls remain in invocation
counts; no-chain source rows have no manufactured core verdict. Absence of an
admitted export is not proof that a raw input was never submitted.

## Trace semantics

Every reference-arm core row receives a source-map ordinal. It retains all
matching external ordinals before filtering. A linked trace includes exact
composite/exposure metadata and raw-exposure digest, task occurrence/capture,
selected follow-up and its operation, exposure invocation plus all attempt
invocations/publications, and outcome/recipe/derivation snapshot references.

Before labeling a trace LINKED_SUPPLIED_LOCAL_EVIDENCE, the reporter verifies
the exact source snapshot/native occurrence/source epoch/capture, original
controller analysis reference, historical analysis prefix replay, requested
purpose, input/output cross-links and all six output byte hashes/lengths. It
checks the frozen recipe relation against the same first selected raw response
for consistency; it does not write a new score or rescore a later response.
Controller-store original analysis and OutcomeStore analysis copy have distinct
store/ref identities, but identical byte digest/length. Their identities must
not be collapsed.

Positive and reasoned native-hold examples are selected only from linked traces
in this exact scope. A multi-publication hold shows all calls/publications causing
the hold. If either kind is absent or linkage is incomplete, the example says
NOT_AVAILABLE. Two distinct demonstration cohorts stay distinct; no merged N is
invented to force both examples into one report. Historical rows stay immutable
when later source revisions appear.

RECONCILED_DECLARED_SCOPE means the declared engineering inputs/inventories
reconcile. DIAGNOSTIC_INCOMPLETE preserves unresolved/mismatched comparisons,
missing inventory/linkage, failed/pending derivations, pending native operations
or invocations, separate batch failures, and orphan snapshots. Neither state
establishes native truth, source completeness beyond the declaration, usefulness,
UF5 significance, reader access, rights or scientific readiness.

## Explicit output boundaries

`write_handoff(report,new_root,mode='RESTRICTED')` creates only a new directory
with fixed report/ledger/source-map/trace/summary filenames plus STARTED,
MANIFEST and COMPLETED receipts. It does not copy raw source files or key_registry.
Restricted machine ledgers may contain sensitive source identities, descriptors
and internal evidence; keep this local payload restricted. Ordinary input text
is data, not instructions. No execution follows Markdown/JSON content.

`mode='READER_CANDIDATE'` writes only a closed aggregate candidate JSON and fixed
Markdown summary. Raw responses, prompts/generation/captures, native identities,
profile/key material, paths and internal QA/strategy fields are excluded by an
explicit field/value allowlist. Count values must be bounded integers and states
must be known enums. This is a candidate for access/rights review, not an
anonymization guarantee or public release approval; even aggregates may require
review. No automatic publishing or permission claim occurs.

Files/directories are created as0600/0700. The writer is exclusive, bounded at
16MiB per payload/64MiB total and does not overwrite, retry, recover or clean up a
partial root. An exception may leave STARTED and partial payloads; preserve them
and choose a new authorized root/version for any later repair. `verify_handoff`
requires COMPLETED, exact filename/mode/permission/link inventory, hashes and
cross-file consistency; a reader candidate must satisfy the closed allowlist.
It does not validate scientific truth or provide signed/tamper-resistant custody,
power-loss qualification, concurrency rollback or release authority.

## Preserved boundaries

All present worked paths are source-shaped synthetic mechanical QA, not native
observations. Y_next NOT_MEASURED/NOT_VALIDATED_HERE, UF1–UF6 NOT_ADJUDICATED and
JLA INSUFFICIENT_EVIDENCE remain unchanged. Four archived D2 cases
D3-00014/00029/00044/00059 remain ADMIT/primaryJOINED/physicalMISMATCH,
actual-registry false/reported true, prompt AND generation actually different;
not mitigated. Their fixed historical boundary appears in both output modes;
archive hashes are checked separately, without core/HMAC/join rerun. Same G0 root,
historical count/balance unresolved, no reset. WP10, native readiness, actual
material/rights/freeze, scientific adjudication and submission remain separate.

## 1.8.1 repair

Reader candidate labels the four fixed historical identifiers archived_case_id; it never emits the per-run input_ref field. Restricted reports retain original input_ref labels. Source1.8.0 and its failed privacy assertion remain preserved; no case/status is removed and no privacy assertion is weakened.
