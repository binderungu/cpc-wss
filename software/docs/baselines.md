# WP08 offline full-information comparison

`baselines.py` implements WSS V2 D04/U3 and WP08/Q09. It is a generic local
comparison layer, not a native checkpoint, experiment, or utility adjudication.

`capture_native(controller, analysis_ref)` explicitly reads the immutable local
WP03/WP07 prefix and referenced source snapshots, selected follow-up transport
and raw response, current head at read, and readiness declarations. It never
calls the PHP helper, Moodle, LIRA, DB or provider. Typed-event/reference100000 and64MiB
capture bounds refuse oversized inputs; they do not silently truncate. Only
typed controller references in the declared prefix and validated capture manifest/raw/blob refs are followed; arbitrary payload bytes never create pointers; unreferenced orphans
and other source-only workflow grains need their own reconciliation. No proof
of native truth, external authority or continuous freshness follows.

`CommonEvidence` freezes unique raw input refs/bytes, AdmissionContext, native
evidence, exact final exposures, every received typed external row, JoinPolicy,
and explicit auxiliary immutable captures. Callers must supply all relevant
actual captures/recipe/material/context sidecars as common auxiliary evidence;
the module neither discovers missing files nor certifies common-input completeness.
Mechanical fixtures include actual new WP05 producer snapshots and recipe bytes,
not only registry digest assertions. All full-information arms get the same object.
The receipt binds typed external semantics as well as raw descriptors, all raw
inputs, profile/key fingerprints/time, native, exposure, policy, and auxiliary
bytes. Key material stays in memory. Inputs are bounded at10000 rows and64MiB
aggregate; unsupported domains fail explicitly before evaluation. Extra raw
inputs/invalid external rows never disappear because an earlier arm refused them.

`evaluate_full(..., method='CPC_REFERENCE'|'B0'|'B2', cohort_ref=...,snapshot_ref=...)`
supplies identical evidence/profile/keys/time to all arms. CPC_REFERENCE uses the
pinned CPC implementation2.0.2/contract2.0.1. B2 independently invokes pinned
rules1.0.1 plus its FIELD_REQUIREMENTS catalogue, without CPC API/validator deciding
its result. B0 is a native-centered proper-use SOP that uses the same independent
rules, has the entire common evidence available, and exposes selected-source/
hold provenance summaries. B0 is not a separately invented algorithm or a
deliberately information-starved latest-status baseline. It may solve everything
CPC solves. Shared rule specification/catalogue, upstream capture, frozen-native
mapping and WP07 downstream join are explicit; B0/B2 are not independent replications
of each other. No comparison gets credit for captures withheld from another.

Reference imports are explicit, verified absolute-origin source execution with
no comparator sys.path/pyc lookup. Per-arm engine receipts retain exact version,
manifest/source/schema/catalogue pins, distinct from the common evidence digest.
These are cooperative local provenance receipts, not independent custody or
hostile-process execution attestations. CPC's existing private pinned loader is
reused only for the CPC_REFERENCE arm. Importing baselines.py itself is inert.

Rules1.0.1 accepts UTF8 text HMAC keys while CPC also accepts bytes. B0/B2 use a
lossless bytes→UTF8 text→samebytes transport adapter, with identical actual key
bytes and policy. Non-UTF8 binary keys are unsupported by this comparator and
remain unresolved; no replacement key/default/config/authority is invented.
The original operator context remains frozen and the exact encoding rule is
declared. Each engine receives separate mutable copies; mutations are reported
as operational failures, never leaked back into the common context.

Each input retains raw digest/ref and actual result or unresolved failure. Engine
exceptions, malformed return shapes, dependency failures and wrong raw/identity
bindings remain unresolved; they are not invented ERROR_INPUT/QUARANTINE results.
Valid ERROR_CONFIG remains an actual result and NOT_EVALUATED_CONFIG bucket.
Shared native mapping failures retain the core result plus PENDING and incomplete
status. Sanitized failure receipts record phase/type, not exception text or keys.
No persistent state store/migration/retry is added here; returned immutable
objects may be explicitly saved as new companions. This module performs no
hidden writes or native/provider calls.

`frozen_mapping` applies WP07 semantics to captured facts and exact exposure:
known published invocation, condition/context/source links, first selected
follow-up, close/late flags and publication-before-operation sequence. It does not
compare native seconds with observer microseconds. All full-information arms
share this mapping and WP07 all-row cardinality/reason/type/denominator handling.
Tests compare this shared snapshot adapter to the original live-local WP07 adapter
on positive, missing/invalid exposure, retries, uncertain/multiple publications,
late revision and historical supersession. A captured historical basis never
automatically refreshes when the live controller later changes.

`project_b1` is an explicit lossy projection of ALL supplied raw chains and external
rows, not a CPC-ADMIT-only slice. Its opaque pair key is the digest of a reported
seven-field identity; hashing does not validate that identity. Only key equality,
reported label, scalar descriptor and received cardinality reach B1. Invalid
non-scalar values become a non-scalar marker, not full external metadata. A closed
`AblationRow` cannot structurally carry native/profile/composite/recipe handles.
`evaluate_b1` is pure and retains all duplicate/uninterpretable rows by ordinal.
It reports observed cardinality and always UNKNOWN/ABSTAIN for attribution because
authority/native/input-use evidence is absent. A reported singleton is not a
validated JOINED result. This is an information ablation, not superiority evidence.

`compare_full` checks common access budgets, raw scope, supported arm/engine
receipts, and compares disposition and exact normalized export per input_ref.
Join rows and denominator differences are separate; diagnostic wording may differ
without changing semantic parity. Any unresolved input or mapping failure yields
INCOMPLETE_EVALUATION, even if both arms fail alike. Other semantic differences
yield MISMATCH_REQUIRES_DIAGNOSIS, treated first as bug/spec/access mismatch. MATCH
is legitimate and does not establish novelty, superiority or UF5 handoff value.
Constructed comparison dictionaries are supplied assertions, not a proof that
an engine ran; use retained actual evaluation receipts for evidence.

All new fixture rows, keys, source transports, rubric and actual producer calls
are synthetic mechanical QA. No JLA/UF1–UF6/pedagogical/security/performance
readiness claim follows. Y_next stays NOT_MEASURED/NOT_VALIDATED_HERE, JLA
INSUFFICIENT_EVIDENCE unchanged. Four archived D2 negatives D3-00014/29/44/59 stay
ADMIT/primaryJOINED/physicalMISMATCH, actual-registry false/reported true, actual
prompt AND generation differ from reported approved; unchanged/unmitigated, no
archived core/HMAC/join rerun. Same G0 root/count/balance unresolved, no reset.
No WP09+, manuscript change, public release or submission is performed.
