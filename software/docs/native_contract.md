# SC01 source1.10.0 addendum (normative)

See sc01_response_scope.md: `courseid` stays positive context identity;
`feedback_route=ordinary_course` and explicit `response_scope_courseid=0`
bind the two response scope columns. `target_course_category` must be observed
positive and agree with both retained source-window metadata rows. `course` is
the ninth fixed InnoDB/SELECT table; category0/site Feedback is unsupported.
Wire1.0 and old controller/capture formats are not migrated. Current offline verification is external in
CPC_JLA_WSS_SC01_SEMANTIC_REPAIR_V1_20261020. No live readiness is established.

# WP01 native and history record contracts

This defines immutable offline record shape and binding diagnostics. Mechanical verification is recorded separately; no native source truth or execution authority is established.

`src/wss_bridge/native_contract.py` provides frozen dataclasses with closed
`from_mapping` parsers and independent `to_mapping` dictionaries:

| Type | Meaning |
| --- | --- |
| `SourceIdentity` | Source epoch, instance, source-version and runtime-version references. Epoch scopes the native numeric IDs across restores/resets. |
| `ActorBinding` | Explicit local actor/registry reference and expected synthetic Moodle user ID. A declared binding is not verified registry evidence. |
| `NativeTarget` | Declared epoch/course/cmid/Feedback/item/context/event bindings, expected item type, and expected item/value/presentation digests. No implicit current course or actor. |
| `NativeOccurrence` | Reported native standard-log row and exact event, context, initiating/owner/real user, origin, anonymity and native time fields. |
| `NativeValueSnapshot` | Reported completed/item/value identities, bindings, modification time and restricted source-content references plus digests. |
| `NativeReadReceipt` | One observation of one operation, retaining every supplied occurrence/snapshot, source/read context and diagnostics. |
| `LedgerRecord` | Immutable, typed reference/history container for the separate workflow grains. |

Identifiers are nonblank exact strings. Numeric native IDs are exact nonnegative
integers; booleans, strings, floats and negative IDs are structural errors. Zero
is retained if actually reported by a source; it is never substituted for a
missing ID. Missing source fields remain `None` and serialize as JSON null.
Zero source/target/actor identity IDs produce explicit binding issues; the two response scope fields are not IDs and explicitly allow0 only under the new ordinary-course contract. Source and observer times
require RFC3339 with an explicit timezone. Digest spelling follows the shared
primitives: `sha256:` followed by 64 lowercase hexadecimal digits.

No learner answer bytes or credentials are embedded in these records. Value and
item text use restricted opaque references plus digests. A legitimate empty
source value is representable by a reference to the empty byte object and its
actual digest. There is no nonempty-answer assumption, default zero score,
string-to-number conversion or digest-to-answer reconstruction. Digest/reference
shape validation does not read bytes, confirm a digest, or establish ownership.

`NativeReadStatus` contains `MATCH_OBSERVED`, `NO_MATCH`, `MULTIPLE_MATCH`,
`READ_UNAVAILABLE`, `SOURCE_CONFLICT`, and `NATIVE_RESULT_UNRESOLVED`.
`MATCH_OBSERVED` is a helper-reported observation status, not successful native
verification. Missing, partial, contradictory and multiple-match receipts are
retained. Datatype errors are `ContractError`; semantic source discrepancies are
returned by `NativeReadReceipt.binding_issues()` without deleting or rewriting
observed facts or changing the declared status.

`binding_issues()` reports unresolved source/registry/read/window context,
including `TARGET_REF_MISSING` when a provided target has no target reference,
reported unknown native completion, unsubstantiated clean-interval/sole-writer
references, candidate multiplicity, event/target/snapshot disagreement, missing
exact value and item source refs/digests, and no-impersonation issues. It compares
initiating `userid`, owner `relateduserid` and `completed_userid` against the
expected registry user; a positive `realuserid` yields an impersonation issue,
and a reported zero yields an unresolved binding issue.
`realuserid_observed=True` explicitly distinguishes a source-observed null
from an unavailable field. Event and `other` anonymity fields are retained
separately and must both report false for this route. Context instance and
`other.cmid` are checked independently; item/value/completed/Feedback/course
bindings are checked together. Expected target `item_type` and
`item_presentation_digest` remain optional nullable fields; a missing expected
or observed value produces `ITEM_TYPE_UNRESOLVED` or
`ITEM_PRESENTATION_UNRESOLVED`. Conflicting non-null values produce
`ITEM_TYPE_CONFLICT` or `ITEM_PRESENTATION_CONFLICT`. Source snapshot values and
target declarations are retained unchanged. Watermark/cursor comparisons do not require
consecutive numeric IDs. Missing evidence references produce issues; present
references are only claimed locators and are not verified evidence. Even an
empty issue tuple establishes neither native truth nor authorization.

`native_lira_event_id` is always null for the selected reference-renderer route;
a non-null value is a route-shape error. No ID is generated to fill it.

`classify_observations(previous, incoming)` is a pure source-content comparison:

- Different known `(source_epoch_ref, standard_log_record_id)` identities return
  `NEW_OCCURRENCE`, even when completed IDs and submitted content are identical.
- The same identity and matching native content snapshots return
  `DUPLICATE_OBSERVATION`. Receipt/operation refs, observer time/sequence,
  transaction/read refs, snapshot refs and byte/text/presentation locators do not
  change that classification. Native fields and actual content digests do.
- Known conflicting source/event/snapshot fields for the same identity return
  `SOURCE_CONFLICT`, including conflicts detectable in partial receipts.
- Missing occurrence identity, unavailable essential snapshot identity/digests,
  or unequal knowledge without a known contradiction returns
  `IDENTITY_UNRESOLVED`.

A standard-log row ID must be an exact positive integer to participate in this
identity comparison. A reported zero stays in the receipt and produces issues;
it returns `IDENTITY_UNRESOLVED` rather than naming a native occurrence.

This classification does not select a canonical row, append a receipt, allocate
an attempt, authorize help, resolve an operation or collapse core/external
multiplicity. It neither establishes source-history completeness nor reconciles
an unexplained mutation without an occurrence. Both records remain available to
the caller for later policy decisions.

`LedgerRecord` serializes exactly four top-level keys: `record_ref`, `kind`,
`entity_ref`, `payload`. Record/identity references are required exact identifiers.
Payload objects are deeply copied into immutable mappings/tuples; mutable JSON
copies are returned by `to_mapping`. Additional generic payload metadata is
allowed but must be supported JSON with no floats, cycles or arbitrary objects.
Top-level unknown keys are rejected. Present fields ending in `_ref` must be
identifier strings or explicit null; required identity refs cannot be null.

The following generic payload fields are required:

| `RecordKind` | Required payload fields |
| --- | --- |
| `OPPORTUNITY` | `opportunity_ref`, `actor_ref`, `target_ref`, `status` |
| `SUBMIT_OPERATION` | `operation_ref`, `actor_ref`, `target_ref`, `status` |
| `NATIVE_OBSERVATION` | A `NativeReadReceipt` serialized mapping; nested source contracts are closed. |
| `ATTEMPT_REFERENCE` | `attempt_ref`, `occurrence_ref`, `status` |
| `INVOCATION_REFERENCE` | `invocation_ref`, `attempt_ref`, `status` |
| `PUBLICATION_REFERENCE` | `publication_ref`, `invocation_ref`, `status` |
| `FOLLOWUP_REFERENCE` | `followup_ref`, `attempt_ref`, `occurrence_ref`, `status` |
| `CORE_INPUT_REFERENCE` | `input_ref`, `invocation_ref`, `status` |
| `CORE_RESULT_REFERENCE` | `input_ref`, `evaluation_state`, `disposition` |
| `MAPPING_ASSESSMENT` | `input_ref`, `mapping_status`, `reason_flags` |
| `EXTERNAL_ROW_REFERENCE` | `row_ref`, `attempt_ref`, `status` |
| `JOIN_ASSESSMENT` | `input_ref`, `terminal_reason`, `reason_flags` |
| `ANALYSIS_SNAPSHOT_REFERENCE` | `snapshot_ref`, `status` |
| `FAILURE` | `operation_ref`, `layer`, `status`, `code` |
| `AUDIT_REFERENCE` | `audit_ref`, `status` |

`entity_ref` must exactly equal the primary payload reference for its kind:

| `RecordKind` | Required equality with `entity_ref` |
| --- | --- |
| `OPPORTUNITY` | `payload.opportunity_ref` |
| `SUBMIT_OPERATION` | `payload.operation_ref` |
| `NATIVE_OBSERVATION` | `payload.observation_ref` |
| `ATTEMPT_REFERENCE` | `payload.attempt_ref` |
| `INVOCATION_REFERENCE` | `payload.invocation_ref` |
| `PUBLICATION_REFERENCE` | `payload.publication_ref` |
| `FOLLOWUP_REFERENCE` | `payload.followup_ref` |
| `CORE_INPUT_REFERENCE` | `payload.input_ref` |
| `CORE_RESULT_REFERENCE` | `payload.input_ref` |
| `MAPPING_ASSESSMENT` | `payload.input_ref` |
| `EXTERNAL_ROW_REFERENCE` | `payload.row_ref` |
| `JOIN_ASSESSMENT` | `payload.input_ref` |
| `ANALYSIS_SNAPSHOT_REFERENCE` | `payload.snapshot_ref` |
| `FAILURE` | `payload.operation_ref` |
| `AUDIT_REFERENCE` | `payload.audit_ref` |

An opportunity has its own pre-anchor `opportunity_ref`; actor and target refs
are relationships and cannot stand in for that identity. `record_ref` names
each history entry, allowing distinct entries about the same entity. Failure
entries describe their preallocated operation; core results and assessments
describe their input. A mismatching entity reference is a structural error;
the parser neither rewrites it nor treats it as an alias. This local equality
check does not resolve any cross-record relationship or prove referenced
entities exist.

Statuses/layer/code/terminal-reason strings are explicit nonblank identifiers;
this foundation does not recognize them as lifecycle transitions. Reason flags
are retained in supplied order as immutable arrays. Mapping status is exactly
`PENDING`, `HOLD` or `ELIGIBLE` and remains separate from a CPC result.

For core-result references, `EvaluationState.COMPLETED` requires a disposition
of `ADMIT`, `REJECT`, `QUARANTINE`, or `ERROR_INPUT`. `PENDING`, `API_FAILURE` and
`NOT_EVALUATED_CONFIG` require null disposition. `API_FAILURE` and
`NOT_EVALUATED_CONFIG` also require `error_ref`. `ERROR_CONFIG` is never a core
disposition; a configuration issue is retained as a failure and an unevaluated
input reference. The fifth reporting bucket is `NOT_EVALUATED_CONFIG`, separate
from the four dispositions. API failures remain unresolved evaluation refs,
not invented `ERROR_INPUT` decisions. A status recorded here does not prove an
actual core call occurred, a result is genuine, or reconciliation is complete.

Record/operation/attempt/invocation/snapshot/native/completed identifiers remain
separate. The generic payload has no cross-record uniqueness, admission,
publication, eligibility, chronology or canonicalization authority; those later
interfaces require separately authorized work. This module has no DB, network,
credential, filesystem-read, signer, helper, controller, renderer or CPC import.

Offline verification and independent-review receipts are versioned outside source. Source/record validity is not native truth or permission.
