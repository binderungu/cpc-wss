# WP06 generic offline CPC adapter — source 1.5.0

Implements offline plan WP06/Q02. Pinned CPC2.0.2 source and sibling schemas use
contract2.0.1/schema cpc-2.0.1. Adapter does not change its rules or implement a
replacement validator, outcome engine, native reader, comparator or study runner.

## Context and input boundary

AdmissionContext(profile,key_registry,validation_time) copies/freezes the supported
workflow JSON domain and bytes key material. Invalid supported JSON configurations
are passed to actual CPC profile checks/API and can return ERROR_CONFIG; no parse
success or hash is authority. Key registry is memory-only, aggregate<=1MiB with
depth32/cycle bound; snapshot has only a deterministic typed root fingerprint,
including invalid int/bool/null/nested registry forms. Profile/time/fingerprint
receipt is <=1MiB. Unsupported configuration objects/floats/surrogates fail at
constructor boundary, not as fabricated CPC dispositions.

CPCAdapter.create(newroot,context,run_ref) explicitly creates exclusive local
metadata, ledger and snapshot store. Batch context digest and exact validation
time are bound before calls and checked on replay; chain never selects its own
profile/keys/time. Keys remain external to persisted receipts (test keys are
SYNTHETIC_ONLY literals, never deployment credentials). Pinned source is verified
before loading exact paths into a private namespace; no shadow global cpc2 or
implicit source .pyc write. An initially verified in-process module cache and
cooperative interpreter are assumed; no hostile-process trust guarantee.

.evaluate(raw,input_ref=None) allocates a local receipt identity, persists
RECEIVED/raw/requested-ref bytes BEFORE profile/API dependency work. Auto refs
use a short base36 per-batch namespace and fit the actual allowed identifier
bound; uniqueness is checked only in this batch. Explicit duplicate, invalid or
over-bound refs remain received/unresolved; unsafe ref strings have no invented
valid input_ref and retain an explicitly typed bytes snapshot. No nearest-time,
case-ID or content hash is an attempt identity. Same case metadata can occur on
multiple operator refs without hidden deduplication.

Raw bytes/str go unchanged to validate_raw(...,input_ref=ref). Bytes remain bytes;
valid strings save UTF8; unencodable Python strings save surrogatepass bytes
labeled STR_SURROGATEPASS_NOT_VALID_UTF8 while the exact string reaches the API.
This is not claimed to be valid UTF8. Dict/list/scalar misuse is saved as tagged
NON_TRANSPORT_JSON_API_MISUSE for audit and passed as the original wrong type,
so the actual API raises TypeError; it is not serialized into a valid raw chain.
Arbitrary nonrepresentable objects/oversized retention inputs are explicit local
failures, not generated ERROR_INPUT. WP01 retains at most16MiB per snapshot; raw
str length precheck avoids unbounded encoding allocation. Actual core byte/depth/
record/identifier limits are never widened by the adapter.

## Results, failures and denominators

Returned JSON value is persisted verbatim in content before partition/identity/
hash checks. Pinned partition_results validates result shape, unique refs and
admitted whitelist; adapter also matches input_ref and exact API transport hash.
Only then RESULT_RETAINED is recorded. ADMIT/REJECT/QUARANTINE/ERROR_INPUT and
ERROR_CONFIG remain actual CPC results. During export ERROR_CONFIG maps only to
NOT_EVALUATED_CONFIG as defined by the pinned export layer.

API TypeError/ValueError/RuntimeError, missing profile/schema/API dependency,
wrong returned identity/shape, duplicate ref or capture/ledger failure does not
become a fake REJECT/ERROR_INPUT/sixth core disposition. Raw/partial/orphan/actual
returned bytes remain. An EvaluationReceipt returns UNRESOLVED with a closed
failure code and no fake result; further dependent work stops. Exception args/
text/tracebacks, which might contain keys, are not written. Failed writes are not
retried/truncated/repaired. Ledger IO uncertainty poisons writable handle.

Interim durable received receipts = retained core-result buckets + unresolved
receipts. This is an evaluation-receipt denominator, not native attempts/learners.
Duplicate explicit refs retain distinct receipt identities and force incomplete
status. Evaluation accounting and export completion are separate; pending or
failed export remains INCOMPLETE even if evaluations all completed. Read-only
replay needs no functional core import just to enumerate previously retained
facts; it revalidates file hashes, context, row identity/event order and referenced
raw/ref/result bytes. Pinned partitioning is repeated for actual export.

Readonly/stopped/sealed/corrupt-storage preconditions can refuse before intake.
No local system can guarantee a new durable receipt when storage itself is
unavailable: caller must retain returned unresolved receipts/exceptions and
reconcile against ledger/orphans. A missing journal event is not proof no call
was attempted. No writable reopen/resume/export-after-failure API exists.

## Whitelist export and replay

.export() requires no unresolved evaluation and no prior export attempt. It
records EXPORT_STARTED before dependency/preflight work, then pinned partition
checks, exclusive root/export directory and admitted.jsonl/exclusion_ledger.jsonl/
accounting.json writes, file+directory fsync and readback, then EXPORT_COMPLETED.
Admitted rows contain exactly the existing eleven normalized metadata fields,
never response bodies/outcome values/capture keys. Exclusions retain actual
sanitized diagnostics. Core raw returns stay in internal snapshots, separate
from the whitelist. No public/research-data release permission is inferred.

Collision, partial write/fsync/readback or final journal failure retains files
and incomplete status; no overwrite, rollback, transaction or publication-safety
claim. A readonly open verifies expected context/run, ledger and all referenced
snapshot/export bytes. It cannot resume writes or rerun admission silently.
The local integrity scheme is cooperative/hash-linked, not WORM or proof against
a malicious process rewriting both data and hashes. Whole-batch replay/export
is in memory; no throughput/storage-growth/power-cut qualification is claimed.

## QA and claims

New labeled fixtures independently build/sign metadata-only assignment/outcome
assertions around actual WP05-produced synthetic exposure. These are helper
fixtures for actual CPC API/partition comparison, not WP07 scoring/native
outcome observations, archived D1–D3 replays or a full WSS worked demonstration.
Passing admission checks the supplied assertion relations, not their physical
truth. Four archived D2 counterexamples remain ADMIT/primaryJOINED/physical
MISMATCH with both actual prompt and generation different, unchanged/unmitigated.
No archived HMAC/core/join rerun, Moodle/LIRA/nativecheckpoint, manuscript,
WP07+ or scientific experiment. Y_next and JLA insufficiency unchanged; G0same
root/count/balance remain unresolved without reset.
