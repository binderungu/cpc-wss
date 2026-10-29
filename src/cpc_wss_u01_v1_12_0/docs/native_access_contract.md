# SC01 source1.10.0 addendum (normative)

See sc01_response_scope.md: `courseid` stays positive context identity;
`feedback_route=ordinary_course` and explicit `response_scope_courseid=0`
bind the two response scope columns. `target_course_category` must be observed
positive and agree with both retained source-window metadata rows. `course` is
the ninth fixed InnoDB/SELECT table; category0/site Feedback is unsupported.
Wire1.0 and old controller/capture formats are not migrated. Current offline verification is external in
CPC_JLA_WSS_SC01_SEMANTIC_REPAIR_V1_20261020. No live readiness is established.

# WP02 native read candidate: explicit access contract

2026-10-20. Source1.10.0 access policy. PHP8.4.26 CLI is available for offline fake-provider verification; outcomes are recorded in the external SC01 packet. No live read or checkpoint is authorized by this source.

The candidate targets **64-bit PHP 8.2+**, PDO MySQL with strict TLS attributes,
MySQL 8.x or MariaDB 10.x, nine owner-verified InnoDB tables, and the archived
Moodle Feedback/standard-log schema. This is an explicit supported candidate,
not a claim about the installed sandbox. Other backends/schema versions fail
closed. No schema discovery, sqlite substitute, migrations or automatic repairs
are supplied. The owner must separately verify actual server version/schema,
character conversion, transaction semantics, native logging visibility, principal
permissions, isolation from real users, stable DDL, clean interval/prior operations,
sole writer, actor/context/content map, grants and read scope before live use.
The helper's declared locator strings do not establish any of these facts.

## Inert entry point and explicit live boundary

`native/read_feedback.php` uses namespace `WssNative`. Inclusion declares source
only and reads no files, environment variables, database, Moodle runtime or LIRA.
No-argument/help entry points only print a fixed help string. The direct CLI guard
requires a nonempty string main SCRIPT_FILENAME and compares the first internally
recorded included-file name to `__FILE__`, with
no `realpath`/filesystem probe on inclusion. Absolute and relative main-script
invocations are intended to dispatch; php-r/stdin includes remain inert.
Executed coverage is recorded in the external verification receipt. `cli()` can also be
called explicitly from a future authorized wrapper.

The only live CLI shape is `--execute-read --operator FILE --request FILE`, in
that order, with no optional/default paths. The flag is an execution interlock,
**not user/owner permission**. Such a live command is not authorized now. The CLI
reads two bounded JSON files only after exact argument validation, validates their
closed fields, then calls the live-only `PdoProvider::fromEnvironment()`. Input
files cannot be final-component symlinks. Ancestor symlinks and replacement races
are not eliminated: the operator must control the private input directory.
Nothing is persisted by the helper, including output snapshots or acknowledgments.

`parse_inputs(string $operatorJson, string $requestJson): array` is pure apart from
runtime introspection of integer width. `read_once(QueryProvider $provider,
array $inputs, string $evidenceClass): array` performs exactly one read through an
explicit provider; the supplied QueryProvider is a trusted driver/fake seam, not
an authenticity oracle. No loop, sleep, submit, controller, outcome recipe, source
mutation or next-step unlock is implemented. `QueryProvider` exposes `begin`,
`rows(queryName, sql, params, limit)` and `rollback`.

## Input: no fabricated actual configuration

No operator/request instances are bundled for live use. The only populated input
is synthetic source in the PHP fake-provider test files. JSON rejects duplicate keys,
floats/nonfinite values, invalid UTF-8/surrogates, integers outside 64-bit range,
unknown/missing keys, more than 16 nesting levels, and more than 256 members per
container. Each operator/request input is at most 65,536 bytes. Identifiers use
nonblank UTF-8, no control/format/surrogate characters and at most 256 UTF-8 bytes.
Native target/actor IDs are positive exact JSON integers. No bool-to-int coercion.

Request has exactly `observation_ref`, `operation_ref`, `observer_sequence`
(nonnegative integer), and `log_watermark` (nonnegative integer). These are caller
references/cursor declarations, never evidence of a completed native operation.

Operator has exactly these fields:

- `source`: all four WP01 SourceIdentity fields, each a nonblank reference.
- `target`: all 16 WP01 NativeTarget fields, with positive native IDs, contextlevel
  70, eventname `\mod_feedback\event\response_submitted`, objecttable
  `feedback_completed`, nonblank item type, and three required SHA-256 digests for
  approved item name, item presentation, and prospective controlled value.
- `actor`: all three WP01 ActorBinding fields, with a positive expected userid.
- `table_prefix`: nonempty ASCII letter followed by up to 49 ASCII letters,
  digits or underscores; quoted fixed identifiers only. `backend` is `mysql8` or
  `mariadb10`; `other_encoding` is `json_object` or `php_array_scalars`.
- Nonblank `read_context_ref`, `transaction_ref`, `connection_ref`,
  `target_window_before_ref`, `target_window_after_ref`,
  `sole_writer_evidence_ref`, `schema_policy_ref`, `read_scope_ref`,
  `readonly_principal_ref`, `consistent_engine_policy_ref`.
- `clean_interval_evidence_ref`, `prior_operations_evidence_ref`: nullable
  references; at least one is nonnull. This is a declared prerequisite, not proof.
- `native_result_known`: exact boolean, supplied independently; false preserves
  `NATIVE_RESULT_UNRESOLVED`, never infers success from an observed row.

Source/target epochs must agree. The prefix is not inferred from Moodle config.

The explicit live factory requires `WSS_DB_HOST`, `WSS_DB_PORT`, `WSS_DB_NAME`,
`WSS_DB_USER`, `WSS_DB_PASSWORD`, `WSS_DB_TLS_CA`. There are no defaults. Host is
explicit ASCII DNS/IPv4 text, not `localhost`, a socket or a DSN; port 1..65535;
database ASCII alphanumeric/underscore. An accessible CA file and driver support
for SSL CA/server verification, disabled multi-statements, native prepared
statements, nonpersistent connections and strict exceptions are required.
`charset=utf8mb4` is fixed. These safeguards need actual backend qualification;
TLS negotiation, read-only grants and the meaning of the selected principal are
not proven by environment fields or a successful connection. No secrets, DSN,
SQLSTATE, raw query text or driver exceptions are returned. Invalid pre-parse
CLI input receives fixed sanitized messages. A connection/driver failure after
valid input emits an empty structured READ_UNAVAILABLE receipt with the supplied
operation/observation references and READ_FAILED_BEFORE_PROVIDER, plus nonzero exit.
Library callers should retain the same error boundary.

## Read projection and failure semantics

The same PDO connection issues only fixed `SET TRANSACTION ISOLATION LEVEL
REPEATABLE READ`, `START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY`, prepared
SELECTs, and `ROLLBACK`. No Moodle bootstrap/config/API, flush/dispose, tmp tables,
writer calls, global setting, session/cache operations or native data changes.
The fixed transaction-local SET selects the next transaction; it is not a global
setting. A backend-specific fixed session-status SELECT requires exactly one
nonempty `Ssl_cipher` before target/data reads: MySQL uses
`performance_schema.session_status`, MariaDB uses `INFORMATION_SCHEMA.SESSION_STATUS`.
A missing/empty/inaccessible TLS status fails closed. Requested PDO attributes
and this post-connect check still need client/TLS/identity qualification; a
post-connect check cannot undo a possible handshake downgrade. A START failure
following SET does not establish a read snapshot and is READ_UNAVAILABLE; only
successfully begun reads can report consistent_snapshot_observed. An INFORMATION_SCHEMA query checks exactly the nine referenced tables (including course)
against an InnoDB policy; VERSION selects the declared supported backend family.
These queries do not prove sole-writer, principal rights, stable schema or source
authenticity. Consistent snapshot does not block writers or recover overwritten
historical answers. ROLLBACK closes the read transaction; a failed close is a hold.

The helper checks the declared course/module/context/Feedback/item mapping before
and after in that same snapshot. Exact known fields are compared; left joins keep
missing/misbound native facts from becoming false matches. An invalid before-map
returns SOURCE_CONFLICT (or NATIVE_RESULT_UNRESOLVED when the supplied native
operation-result declaration is false) with diagnostics and captured target metadata immediately
after closing the read transaction: no event/completed/value query is issued. The end cursor is the
MAX target-log ID for declared course/cmid/event and expected userid **or**
relateduserid. A reset below the supplied watermark is a conflict. Candidates
are ascending native IDs in `(watermark, cursor_end]`, capped at 17 (16 plus an
overflow sentinel). All returned occurrences are retained. No latest/nearest/hash
selection and no deduplication by completed/content ID occur.

Each retained candidate must pass exact eventname/objecttable/context/course,
initiator/owner, decoded cmid/instanceid/anonymity, no-impersonation, positive native
IDs and cursor-window checks before any completed/value query. A bad anchor stays
in the receipt with diagnostics and raw sidecars but triggers no completed read.
This check is per candidate, independent of previously accumulated diagnostics.
For each passing actual event objectid, completed metadata is read directly. Value bytes
are read only when completed owner, Feedback, explicit response-scope0 and anonymity agree with the
expected synthetic context. An owner mismatch retains metadata and a conflict but
**does not issue the value query**. Values are selected by completed ID and the declared expected item only,
without filtering away wrong course/tmp/item-parent/type bindings, and include `feedback_value.id`,
completed/item/course, tmp_completed and actual item metadata. Per-completed/expected-item
value rows are capped at 17; unrelated item answers are not exported. A missing
expected-item row is VALUE_MISSING/SOURCE_CONFLICT, not a borrowed answer. More than one value/occurrence remains ambiguous.
WP01 snapshot fields are emitted unchanged; native source facts are never replaced
with prospective input, fake IDs, observer time, registry-copy content or a default
benign value. Missing native timestamps remain null; unix 0 is the real UTC epoch. Empty,
nonstring or invalid UTF-8 eventname/objecttable/origin/item-type source fields
become null plus an explicit diagnostic for WP01 compatibility; string bytes
(including empty/invalid UTF-8) remain at raw blob references in metadata, with
no trim or surrogate replacement.

Raw values, `feedback_item.name`, presentation, and event.other are exact returned
column bytes under the declared utf8mb4 connection; there is no trim, HTML
execution, object deserialization or normalization. PDO connection conversion
must be qualified separately: this claims returned-column bytes, not arbitrary
physical on-disk encoding. SQL projects a column as null when OCTET_LENGTH exceeds
262,144; actual reported length and an explicit diagnostic are retained, with no
substitute bytes/digest. Limits mean the read is partial and held.

`other` is decoded only by the explicitly selected bounded decoder. Strict JSON
must be an object of scalar null/bool/int/string values, with no duplicate keys.
The custom PHP subset supports a top-level serialized array with string keys and
scalar values only: null, boolean, integer, byte string. Objects, references,
arrays as values, floats, duplicate keys and unsupported tokens fail closed.
No `unserialize` or `eval` is used. Unknown keys preserve raw bytes plus conflict.
The archived Moodle constants use **1=anonymous, 2=non-anonymous** for
completed.anonymous_response and deprecated other.anonymous. Standard-log anonymous
uses 0/1. The helper maps these distinct enums to nullable booleans, never treats
Moodle enum 2 as PHP truth. Unknown/missing values stay unresolved.

Status is reported shape/consistency only: `MATCH_OBSERVED`, `NO_MATCH`,
`MULTIPLE_MATCH`, `SOURCE_CONFLICT`, `READ_UNAVAILABLE`, or
`NATIVE_RESULT_UNRESOLVED`. Diagnostics and partial rows survive failures; a PDO
exception becomes only `READ_FAILED_SANITIZED`. `MATCH_OBSERVED` does not verify
native truth, grants, eligibility, historical identity, lost events or publication.
WP01 binding diagnostics and future controller decisions remain separate.

## Exact transport and local byte addressing

Transport has exactly `transport_version=wss-native-read-1.1`, `evidence_class`,
`receipt`, `blobs`. The CLI stamps `REPORTED_NATIVE_READ`; fake-provider tests
stamp `SYNTHETIC_OFFLINE_FIXTURE`. These are declarations, not cryptographic source
attestation. Receipt has exactly the existing WP01 NativeReadReceipt.to_mapping
fields; `native_lira_event_id` is always null. No LIRA operation is performed.

Every blob has exactly `ref=blob:<64 lowercase sha256 hex>`, `sha256=sha256:<hex>`,
`byte_length` and `data_base64`. At most 128 blobs, 262,144 bytes each, 4 MiB total
raw bytes, 8 MiB transport bytes. Identical byte blobs share one local ref; all
occurrence/snapshot rows remain. No byte-addressed ref becomes native identity.
Target-window and completed metadata also have local metadata blobs, so
partial failures do not erase already read metadata. Snapshot rows are capped at 32; the explicit `SNAPSHOT_ROWS_OVERFLOW` diagnostic
holds the read and the bounded rows remain. This cap does not claim complete
capture of a larger candidate set.

Item/presentation/value refs resolve to their raw blobs. Each snapshot_ref points
to a metadata blob recording native log ID, raw-other blob ref, snapshot fields,
reported tmp_completed and original column lengths. A separate event provenance
blob links each native occurrence to raw-other bytes even if completed/value rows
are absent or other decoding fails. Metadata blobs are local JSON encodings of
reported metadata, clearly separate from exact raw source bytes. They are not
Moodle rows or authority. Bag membership is retained; no consumer should infer
mapping from blob order. Future WP03 must persist the entire receipt/sidecar set
before acknowledgment; that controller behavior is outside this source.

## Offline source tests and remaining qualification

`native/test_read_feedback_offline.php` contains 23 fake-provider methods covering
strict parsing, scalar-array rejection, exact transport/bytes, enum mapping,
multiple occurrences, wrong owner, wrong bindings, zero ID, no match, unknown
operation result, cursor reset, byte limit, overflow, target changes, unsupported
engine/backend, sanitized partial failure, failed read close and byte dedup/capacity and a TLS-session guard.
It includes only the helper and synthetic fixtures. It neither constructs PDO nor
reads credential environment variables. Fake-provider execution, lint and transport results are recorded externally for source1.10.0. They are not actual MySQL/MariaDB qualification, query-plan/timeout qualification, native logger/checkpoint, access permission or manuscript evidence. The new test_sc01_offline.php adds source-faithful scope0 and negative controls.

The original four D2 counterexamples D3-00014, D3-00029, D3-00044 and D3-00059 remain
ADMIT / primary JOINED / physical MISMATCH, with actual prompt **and** generation
different from approved/reported values. This helper does not mitigate a lying
observer or promote CPC declarations to independent truth. No JLA sufficiency,
learning/causal effects, utility improvement or production security claim follows.
