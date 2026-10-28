# WP07 selected-source outcomes and WSS join — source1.6.1

Behavior follows WSS V2 N7–N9/offlineWP07/Q08. No core schema/rules/old D3engine
change. All authority/review/source statements remain supplied declarations.

## Recipe and source lineage

OutcomeRecipe(raw) accepts explicit canonical UTF8 recipe format
wss-response-recipe-v1 with rubric_id/version, task_version_ref, expected followup
item/presentation digests, review/rights opaque refs and finite response lookup
(1–256 exact strings, each score exact int0–4). Missing refs/malformed type fail;
valid references/bytes/lengths do not prove approval or pedagogical validity.
Actual final WSS task/rubric remains pending. No automatic grading recipe chosen.

score(rawbytes) performs exact UTF8 text lookup only, no trim/int coercion/hash/
verdict/admitted-composite scoring. Emptybytes→MISSING/None; unknown/invalidUTF8→
INVALID/None; explicit supported answer→VALID/int0–4. Blank is not defaultzero;
boolean/float/numeric-string external values are invalid. The QA table is an
author-stipulated example domain, not human performance or construct validation.

read_analysis(controller,snapshotref) reads only local evidence under one WP03
shared command lock. It validates registration, exact bytes/expected context,
basis sequence and fresh project_events replay of that exact prefix. It uses
version-pinned private _command/_state/_events, not a native helper. A saved
analysis is not replaced with latest state or a future score-valid response.
Current-head identifier is recorded at this locked read, not continuously watched.
Later appends require a new mapping/analysis; this is not an eternal freshness
or distributed snapshot guarantee.

selected_source resolves attempt.selected_followup to its first prospective
FOLLOWUP operation and accepted capture, rejects postclose selection or broken
source bindings, verifies raw/blobs/metadata/value digest, and keeps source epoch/
log ID/item/completed/value/snapshot/recipe provenance. Source timestamps remain
inspectable metadata. Publication-before-followup uses controller event order;
Moodle native seconds and CPC microsecond/observer clocks are not equated.

OutcomeStore.create(newroot,run_ref) supplies explicit POSIX local ledger/store.
derive(controller,analysisref,exposureraw,recipe,purpose) allocates STARTED before
preprocessing, retains exposure/recipe refs, reads selected source, checks frozen
task/item recipe binding and that the final exposure refers to a known published
invocation of this attempt/condition, then derives exactly one row with a new
opaque outcome_key. It does not call core API or create/sign outcome records;
metadata-only signed outcome statements in QA fixtures are outside this module.

Each derived row has the seven-field composite plus strict state/value/rubric/
recipe/lineage refs, and a companion raw lineage object. Store snapshots retain
analysis, final exposure, recipe, raw selected value, complete supplied native-
shaped transport and derived row. Local source ownership uses source epoch/log
occurrence/item; another derive from the same source in this store is refused,
not cloned to another purpose/exposure/turn or recomputed to rescue a result.
No global cross-store duplicate-proof claim. Recipe revision needs an explicitly
new version/store; callers must retain/reconcile earlier rows rather than silently
filtering them from a common cohort. Existing immutable outcome rows may be
analyzed against newer native mappings without rescore/reselection.

view() exposes all derivation attempts/statuses, input/output snapshot refs,
failure_stage, generated external rows and orphan snapshot filenames; it checks
referenced bytes/stage shapes/order and store metadata. Failed source/recipe calls
retain FAILED; partial IO may leave pending derivations and orphans. Writes fail
closed, no retry/overwrite/deletion/truncation or writable reopen. open_readonly
can inspect scope/bytes without rewriting history. Storage is cooperative/hash-
linked, not WORM/power-loss/hostile-process protection. Same-source first-use
ownership is local-store only, not a global source truth authority.

## Typed rows and native mapping

ExternalRow.from_mapping keeps every supported supplied row, even invalid value,
rubric/state/shape/composite rows. A typed descriptor preserves invalid floats,
NaN/inf, boolean/string/array values and surrogate text without emitting invalid
JSON. Recipe/row domain is bounded; descriptors use an estimated1MiB data budget/
depth32; unsupported/over-bound caller objects fail the analysis explicitly.
All seven interpretable composite fields define identity before measure checks;
invalid composite rows remain in the external ledger as uninterpretable. Equal
row refs/values do not erase duplicate received rows. Full OutcomeStore rows can
be converted with external_from_outcome; raw/numeric values stay out of corewire.

CoreEntry/entries_from_adapter consumes actual retained/unresolved WP06 rows.
It checks supported SDK shape/identity, not admission semantics. Raw supplied
CoreEntry/NativeMapping/ExternalRow values are caller assertions; creating typed
objects does not prove CPC signatures/native observations. Real QA integration
uses actual WP03–06 sources/outputs; pure unit fixtures are labeled synthetic.

mapping_from_analysis is only for ADMIT. Missing map/exposure or open episode is
PENDING; unavailable/conflicting anchor/publication/condition, late/closure/multi/
uncertain-publication/source flags produce HOLD. Otherwise a closed settled exact
one-published-exposure, selected-followup snapshot is ELIGIBLE. All flags survive.
It compares actual exposure content digest/id/unit/experiment/bundle/condition to
core normalized metadata and maps invocation/attempt/source/publication sequence.
It does not infer physical truth, consent, rights or secure observer identity.

## Pure singleton join and accounting

analyze(entries,externalrows,mappings,JoinPolicy,cohort_ref=...,snapshot_ref=...)
requires an explicit declared cohort/snapshot. It performs no file/native/core
IO and never imports archived analytics.adapter.analyze or its64inventory.
Iterables are bounded at10001seen/10000supported rows. All rows in the supported
cohort remain visible; exceeding bounds refuses analysis rather than truncates.
Pure output can be persisted via explicit SnapshotStore.put in a new version.

Composite is exactly experiment_id,experiment_version,unit_token,final exposure
record ID/content digest,outcome_key,purpose. It preserves the pinned CPC wire
identifier domain (including valid Unicode format characters) byte-for-byte,
without additional string normalization. Actual native IDs remain in companion
lineage, not wire extensions.

Count all ADMIT composites before PENDING/HOLD/ELIGIBLE filtering. Count all
received external interpretable composites before value/rubric/recipe/lineage
validity. A held duplicate or same-valued invalid external duplicate cannot
rescue singleton. Policy requires exact rubric identity/version and recipe digest;
only exact int0–4 with VALID state and required lineage can join.

Primary non-ADMIT reasons use actual CORE_REJECT/CORE_QUARANTINE/CORE_ERROR_INPUT/
NOT_EVALUATED_CONFIG; unresolved API receipts use CORE_EVALUATION_UNRESOLVED,
not a sixth coreverdict. ADMIT precedence: NATIVE_MAPPING_PENDING, NATIVE_MAPPING_HOLD,
ADMISSION_COMPOSITE_AMBIGUOUS, EXTERNAL_COMPOSITE_AMBIGUOUS, EXTERNAL_MISSING,
EXTERNAL_MEASURE_INVALID, JOINED. All independent flags remain, not only primary.
Present row with missing value is EXTERNAL_MEASURE_INVALID +EXTERNAL_VALUE_MISSING;
EXTERNAL_MISSING means no row at that key. Missing is never0 or latest-valid rescue.

Reconcile received_core=fivebuckets+unresolved; ADMIT=pending+hold+eligible;
eligible=JOINED+four mutually exclusive joinexclusions. External received=
interpretable+uninterpretable, every row has its own ordinal. Source/attempt/
operation/invocation/publication/outcome counts remain separate grains in their
own views. No single N represents all of them and no no-chain row becomes fake
coreQUARANTINE. Core dispositions never change due to native/join state.

Historical mappings may retain historical JOINED/ELIGIBLE for their exact basis,
but complete_for_declared_snapshot is false if any effective ADMIT map lacks a
verified analysis/head or is superseded at read. Missing map is PENDING and is
included in freshness checks; non-ADMIT mapping entries are rejected. This is a
technical completeness flag for the declared input snapshot only; OutcomeStore
failures/source-only records and other workflow/readiness gates must be reconciled
separately. No auto-native/scientific/release decision follows.

## Preserved claims

Illustrative synthetic score only, Y_next NOT_MEASURED/NOT_VALIDATED_HERE, JLA
INSUFFICIENT_EVIDENCE unchanged. No native/checkpoint/learner study, paidAPI,
WP08baseline/utility, manuscript or public release. Four archived D2 negatives
D3-00014/00029/00044/00059 remain ADMIT/primaryJOINED/physicalMISMATCH, actualregistry
false/reportedtrue and both actualprompt/generation different. No archived core/
HMAC/join rerun, relabeling or mitigation. SameG0root/count/balance unresolved,
no reset. New fixtures/recipes/keys are mechanical QA, not actual material approval.

## 1.6.1 repair and local store format

Direct typed ExternalRow instances normalize metadata with the same rules as
from_mapping, so invalid lineage/row refs cannot bypass checks. Derivation STARTED
receipts retain valid requested_purpose, including refused clone requests. Local
store format is wss-outcomes-v1.1; source1.6.0 prototype v1 artifacts retain their
original reader. No automatic migration or cross-version overwrite is performed.
CPC wire/contract/schema versions remain unchanged. The new tests independently
encode immutable mappings; source1.6.0 and its10 serializer errors are preserved.
