# WP01 ledger and byte snapshots

Authored source only, 17 October 2026. No constructor, storage method, import,
compilation or test has been executed in this stage. Runtime correctness and
failure recovery remain unverified.

## Boundaries

`ledger.py` stores local reference histories. It does not read a Moodle database,
submit an activity, generate help, validate CPC admission or enforce operator
authority. A typed record, hash match or empty diagnostic list is not evidence
that a native observation really occurred. Callers must obtain the relevant
authority before invoking IO; no scope reference grants permission by itself.

`LedgerScope` identifies one local ledger/run/purpose and optional declared source
epoch. These are declarations. `AppendOnlyLedger.create(directory, scope)`
requires an existing real parent and unused leaf; it creates metadata, lock and
empty journal with exclusive file creation and local fsync calls.
`open_existing(directory, expected_scope)` creates nothing and checks the
independently supplied expected metadata, sequence, record shapes and digests.

`append(LedgerRecord)` validates the record representation, holds a cooperative
POSIX exclusive lock, verifies the existing journal, rejects reused workflow
record refs and appends a new canonical line. `read_entries()` returns immutable
data; `read_records()` returns typed records. Native entity/occurrence references
may repeat across distinct receipts. Their multiplicity must not be confused
with the uniqueness of a workflow record ref in this one ledger.

The journal format is `wss-ledger-v1`, encoded with `wss-workflow-json-v1`:
recorded local UTC time, sequence, predecessor digest, typed record and content
digest. The first predecessor is the hash of exact scope metadata bytes; later
predecessors refer to the prior entry content digest. These are **workflow**
digests, not CPC record/proof/commitment digests. Recorded time/sequence are not
a CPC use/commit/release observer or distributed clock. No implicit caller/native
timestamp is synthesized to satisfy attribution.

## Preservation and failures

Existing directories/files are not overwritten. Unknown keys, malformed or
noncanonical lines, duplicate workflow refs, broken sequence/digest and incomplete
trailing records stop use. The library never skips, truncates or repairs a corrupt
journal. Failed creation/append can leave a partial directory or torn suffix;
retain it and report incomplete work rather than deleting evidence or retrying
blindly. A storage exception is not a fabricated CPC refusal.

Finite authoring limits: 4 MiB per journal entry, 64 MiB journal, 10,000 entries, 16 MiB
per snapshot. These are supported-domain guards, not benchmarked capacity or
production readiness. Exceeding a guard raises an explicit error without silent
truncation. A caller whose failure cannot be appended to a full/damaged journal
must preserve/report that unresolved operation outside the failed writer; there
is no automatic claim of complete denominator accounting.

POSIX locks protect cooperating callers only. Source checks refuse symlink paths
and nonregular/hardlinked files, but do not make the filesystem tamper-proof or
provide an atomic snapshot against a hostile same-user process. A party that can
rewrite all files can rewrite an unkeyed hash chain. No WORM storage, independent
custody, anti-collusion, power-loss qualification or global exactly-once guarantee
is supplied. Actual fsync behavior has not been tested here.

## Snapshot store

`SnapshotStore.create(directory, store_ref)` and `open_existing(...)` use a new
store marker. `put(snapshot_ref, immutable_bytes)` writes one exclusively named
byte object and returns `SnapshotReference(store_ref,snapshot_ref,sha256,byte_length)`.
The filename is a hash of the opaque local ref to prevent path interpretation;
it is **not** a native event identity. `get(reference)` checks store binding,
exact byte length and digest before returning bytes. Zero-byte content is valid;
missing content is not converted to empty bytes or a zero score.

A repeated snapshot ref raises `SnapshotExistsError`, even for identical bytes.
The caller must retain distinct receipt history instead of treating a retry as
overwrite permission. Snapshot creation and journal append are separate IO calls,
not a cross-file transaction. A failure can leave an orphan snapshot; it must
remain inspectable and cannot disappear from later controller accounting.

## Shared value primitives

`primitives.py` provides strict identifier/digest/explicit-zone time and typed
integer/boolean checks; duplicate-key/nonfinite/float-rejecting JSON parsing;
deep immutable copies and deterministic UTF8 encoding. Native text/byte content
is stored through protected refs instead of embedded in source contracts. Empty
actual content is not treated as missing. Its depth 64 container guard is a WSS
sidecar bound, **not** CPC 2.0.1's normative root-zero depth 32 input guard. Normalized
signed evidence must still use the pinned CPC interfaces in later authorized work.

## Verification state

Source review only. Import/build/type/lint, component/failure/concurrency tests
and IO smoke checks are `NOT_RUN_USER_SCOPE`. They are required before claiming
executed behavior or using this storage for native/experimental evidence. No live
ledger, snapshot object, workflow record, source fixture or scientific dataset
has been created by executing this implementation.
