# SC01 source1.10.0 addendum (normative)

See sc01_response_scope.md: `courseid` stays positive context identity;
`feedback_route=ordinary_course` and explicit `response_scope_courseid=0`
bind the two response scope columns. `target_course_category` must be observed
positive and agree with both retained source-window metadata rows. `course` is
the ninth fixed InnoDB/SELECT table; category0/site Feedback is unsupported.
Wire1.0 and old controller/capture formats are not migrated. Current offline verification is external in
CPC_JLA_WSS_SC01_SEMANTIC_REPAIR_V1_20261020. No live readiness is established.

# WP03 local controller and episode projection — source 1.2.0

This is a bounded offline implementation of WSS V2 N4–N7. It records supplied
facts using explicit local IO. It cannot launch a helper, submit/poll Moodle,
connect to LIRA, render/publish a response, consume a signing authority, evaluate
CPC or score/join an outcome. No constructor/parser grants those permissions.

## Public API

`ControllerContext` freezes `SourceIdentity`, `ActorBinding`, separate task and
followup `NativeTarget`s, task/context version references, clean-interval or prior
operations evidence, sole-writer evidence and explicit pending-fact codes. These
are declarations, not verification of rights, backend or source truth. Targets
supply approved item/presentation digests; an operation supplies its own
controlled-value digest. Source target/actor/operation/watermark and declaration
references are independently compared against the transport receipt. Empty
pending-facts is not a grant to execute any external action.

`OfflineController.create(new_root, LedgerScope, context)` makes a new local
journal and SnapshotStore and returns the sole writable handle. There is no
writable reopen/recovery API. `open_readonly(root, scope, expected_context)`
checks the independently supplied scope/context and replays all history and byte
references without creating files. `view()` returns a fresh immutable projection.
Imports are inert. POSIX cooperative locks do not protect against a malicious
same-user process replacing storage or rewriting complete hashes.

- `opportunity(note_ref=...)` preserves a pre-anchor funnel entry.
- `begin_operation(opportunity_ref, kind, controlled_value_digest=...,
  log_watermark=..., attempt_ref=None, logical_resource=None, config_id=None)`
  records a prospective local operation. TASK freezes one of WSS-U01-HINT/ANSWER
  and one G_BASE/G_STYLE/G_CAP/G_RATIONALE/G_SEED assignment. FOLLOWUP explicitly
  names an existing attempt, and never changes its assignment. A closed attempt
  can receive a new prospective FOLLOWUP revision only after known closure.
- `record_completion(operation_ref, known=bool, evidence_ref=...)` records the
  supplied operation result exactly once. Unknown result stops the branch and a
  matching transport cannot promote it to known.
- `observe(operation_ref, slot_ms, raw_bytes)` accepts protocol slot labels
  0, 1000, 5000 once/in order, at most three observations. These are not measured
  latencies. There is no sleeping, polling or source access. Raw bytes persist
  and read back before the ingestion event, parsing and interpretation. All
  capture blobs/manifest read back before durable accepted-anchor history and
  ACK. Invalid JSON is retained with INVALID_TRANSPORT. Fatal HOLD prevents more
  prospective visibility observations. Accepted-operation duplicates or late
  audit facts may be retained, but cannot manufacture another anchor for that
  operation. NO_MATCH alone waits to the final slot; binding, scope, conflict or
  completion defects stop immediately. Global log ID gaps are not loss proof.
- `receive_help(attempt_ref, logical_resource=..., config_id=...)` allocates and
  persists RECEIVED before evaluating preconditions. Failed/refused requests
  remain separate invocation entities. Malformed, unsafe or oversized request
  fields are projected to null with explicit INVALID_* reason flags before
  RECEIVED persistence; unsafe raw values are not echoed into the journal.
  Refusals preserve reason flags for
  unknown/closed attempt, pending operation/request, stopped branch, unresolved
  context or condition/resource mismatch. The latter also holds the known
  attempt interpretation. No native LIRA event is fabricated.
- `advance_invocation(ref, stage, evidence_ref=...)` records only ordered stages
  CONSUME_STARTED, CAPTURED, COMMIT_DURABLE and PUBLISHED, with supplied evidence
  references. It does not perform these external actions. `finish_invocation`
  settles NONE/PUBLISHED/UNRESOLVED publication claims; an already known
  publication remains one exposure even when a later call fails; its first
  publication evidence remains unchanged while finish events stay in history.
  Uncertain
  publication holds the episode instead of silently counting zero exposure.
- `close_episode(attempt_ref, reason=ABORT|END_OF_SCRIPT)` records closure.
  A first prospectively bound followup closes automatically, as does a new
  validated TASK superseding the former active attempt. Unsettled requests or
  operations at closure persist CLOSURE_UNRESOLVED; later result facts do not
  rewrite that earlier closure as complete.
- `analysis_snapshot(reason=...)` persists a new immutable analysis view and its
  explicit previous-analysis link. Late event evidence on an already captured
  operation or a post-close invocation result adds HOLD_LATE_EVIDENCE and a new
  analysis version automatically. Existing analysis bytes stay unchanged.

## Identity, episodes and accounting

Native identity is `(source_epoch_ref, positive standard_log_record_id)`.
Repeated identical observation/bytes for an accepted operation adds ingestion,
not attempt. A different native ID may anchor a separate attempt only through
its own prospective operation, even with the same completed/value entity/content.
Same-ID source conflict or reuse across operations holds; it does not choose
latest/first to rescue attribution. Snapshot locators and timestamps are not
native occurrence keys. No native mutation without an event becomes an attempt.

One actor/task has one active attempt. A newly anchored TASK supersedes the
unclosed old episode without moving its help to the replacement. The first
prospectively bound FOLLOWUP is selected independently of score, rubric validity
or condition. Post-close revision requires its own operation recorded after
known closure; arrival time and ID order do not establish outside-window facts.
An extra occurrence observed against an old captured operation is late/unplaced,
never a replacement selected followup. There is no outcome scoring in WP03.

The fresh projection reports separate opportunities, operations, ingestions,
canonical occurrences, attempts, invocations, publications, followups/revisions,
and analyses. They share one physical `AUDIT_REFERENCE` command journal with
versioned event/data payloads, rather than pretending each grain is one common N.
All history is append-only; each logical entity may have multiple history events.
Published exposure is counted once per invocation/publication reference, not per
success/failure stage row. Primary local single-invocation interpretation requires
one known published exposure, a selected first followup, closed/settled episode,
and no independent hold flags. Multiple exposures preserve HOLD_MULTI_INVOCATION;
unknown publication preserves HOLD_PUBLICATION_UNRESOLVED. This is a local
workflow interpretation only, not CPC admission, a native-use result, a valid
external outcome, an empirical effect or JLA qualification.

## Storage and failure limits

One command lock covers replay/preconditions/capture/persistence/append. The
underlying WP01 journal uses hash-linked canonical records and its own lock.
SnapshotStore's immutable names and readbacks are local byte-integrity checks.
Snapshot writes and journal appends are separate filesystem operations, not an
atomic transaction. IO/corruption errors poison the writable handle, leave orphan
bytes/partial journals inspectable and yield no ACK. No overwrite, truncate,
automatic retry, writable recovery, deletion, WORM/anti-collusion or distributed
exactly-once claim is made. Read-only replay validates all referenced bytes and
capture metadata, plus declared context; unreferenced orphan files remain on disk
for manual inspection and are never quietly removed.

The four archived D2 negatives D3-00014, D3-00029, D3-00044 and D3-00059 remain
ADMIT / primary JOINED / physical MISMATCH, with both actual prompt and generation
different from their reported approved values. This controller does not mitigate
a consistently lying observer. Tests use fresh synthetic supplied receipts and
local temporary storage only. Native checkpoint/access and manuscript work are
outside this implementation's scope. Root verification report records executed
checks; this source document alone makes no test PASS claim.
