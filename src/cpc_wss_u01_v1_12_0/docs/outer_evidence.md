# Outer acquisition evidence handoff — source 1.12.0

`outer_evidence.materialize_outer_handoff(campaign_root, unused_new_root)` binds
stored outer grant/preflight/HTTP/helper-process evidence to the inner offline
runner and counterpart artifacts. It performs bounded file reads, hash checks,
JSON indexing and exclusive local writes. It never accesses Moodle, a database,
HTTP, a helper, a provider or a subprocess. No import-time IO is performed.

## Input contract

The parent seals `OUTER_EVIDENCE_MANIFEST.json` **after** the child and the inner
counterpart writer terminate. Its closed schema is:

```json
{
  "format": "wss-outer-acquisition-inputs-v1",
  "mode": "SYNTHETIC_OFFLINE_QUALIFICATION",
  "files": {
    "relative/path": {"sha256": "sha256:<64 lowercase hex>", "bytes": 123}
  },
  "runner_root": "runner",
  "counterpart_root": "counterparts",
  "grant_ref": "freeze/EXECUTION_GRANT.json",
  "preflight_ref": "freeze/PREFLIGHT.json",
  "event_root": "native_events",
  "process_root": "native_reads",
  "child_exit_code": 0,
  "parent_status": "COMPLETED"
}
```

`mode` is either `SYNTHETIC_OFFLINE_QUALIFICATION` or
`BOUNDED_NATIVE_ACQUISITION`; it is a supplied evidence-class declaration, not
proof of native source truth. Child exit code may be null when unavailable.
Parent status is COMPLETED or FAILED. A failed/partial acquisition remains a
valid object of indexing; it does not become a successful worked run.

Each path is a canonical relative POSIX path. The manifest cannot include
itself. All declared payloads must be regular, single-link files under real
directory ancestors, hash/size matched before any output directory is created.
Absolute/parent-traversal/overlapping dedicated roots, symlinks, hardlinks,
duplicate JSON keys and nonfinite numbers are refused. Bounds:20,000 payloads,
64 MiB per file and256 MiB aggregate. These are cooperative local byte checks,
not a hostile-process sandbox, immutable custody or independent authentication.

The parent must exclude `outer_handoff` and this module's final outputs from the
input snapshot. Its final campaign-wide manifest can be sealed afterwards.
Private HTTP/credentials/actual command argv belong outside the selected
handoff snapshot. Paths under a `private` component and `.command.private.json`
are rejected. Public launch-intent receipts must use
`command_public_description`, not an argv array. This local handoff is still
restricted; successful indexing does not authorize public release.

## Inner artifact bindings

The index binds `runner_root/RUNNER_MANIFEST.json`, validates each nested
payload available in the outer snapshot, and similarly binds
`counterpart_root/MANIFEST.json`. The counterpart's copied
`common/RUNNER_MANIFEST.json` must be byte-identical to the runner manifest.
Listed payload/hash contradiction is a hard refusal. Missing nested bindings
are recorded as explicit gaps, not treated as successful linkage.

Both grant and preflight declarations are retained with exact path/hash
locators. No rights, approval, current source identity or grant-to-freeze semantic
validity is inferred from their existence. The parent driver separately owns
grant semantics and frozen input validation. In native mode, a missing or
not-true `native_execution_authorized` declaration makes this handoff
NOT_ASSESSABLE. A true declaration is still not independent authority proof.

## Outer events and HTTP completion

Every event JSON has `kind`, a timestamp field, and dictionary `data`. Supported
timestamp names include `time`, `time_utc`, `UTC`, `utc`, `recorded_UTC`,
`recorded_monotonic_ns` and `monotonic_ns`. An absent timestamp is a visible gap.

- `SUBMIT_INTENT_DURABLE`: `operation_ref`, `kind` TASK/FOLLOWUP. It records a
  charged attempt, not proof of POST transmission or success.
- `ORDINARY_NATIVE_RETURN`: **must include operation_ref**, and boolean `known`.
  A bare completion without operation identity is not silently attached to the
  preceding submit event. Its state remains NOT_ASSESSABLE.
- `READ_INTENT_DURABLE`: `operation_ref`, `read_ordinal`, `slot_ms`; parent budget
  charge is separate from helper launch charge and process-start evidence.

All additional event kinds and fields remain in the common snapshot/index.
Missing return receipts preserve unresolved completion. The module never
creates a successful HTTP completion or modifies the ordinary client's result.

The dedicated event/process directories are inventoried for files omitted from
the selected snapshot. Omitted receipts are explicit gaps; count fields then
remain PARTIAL_UNKNOWN/null, with listed members only a lower bound. Unlisted
contents are not opened. This prevents omission of a failed receipt from
silently producing an exact zero count.

## Helper process accounting

The index joins `read-NNN.intent.json`, `read-NNN.process.json` and parent read
request by ordinal, operation_ref and slot_ms. Positive identity contradictions
are refused. Missing members/fields remain gaps, not false/zero defaults.

The repaired process schema exposes `charged_launch_attempt`,
`popen_attempted`, `process_started`, nullable pid/returncode, terminal/failure
stage and explicit `close_state` (CONFIRMED, UNCONFIRMED or NOT_STARTED).
Available raw stdout is checked against its stored bytes/hash. Missing stdout
or unknown presence remains explicit. Private stderr/argv are not copied merely
to make a public receipt seem complete.

The denominator additions distinguish:

1. Parent durable submit-budget charges, separately TASK/FOLLOWUP.
2. Operation-bound known completion and unresolved completion records.
3. Parent protocol-read budget charges.
4. Durable helper launch-charge intents.
5. Popen attempts and confirmed started subprocesses.
6. Confirmed versus unconfirmed read close, and NOT_STARTED receipts.

A failed Popen can have one budget charge, one Popen attempt, **zero confirmed
started children** and NOT_STARTED close. That zero is supported by an explicit
terminal receipt, not by missing evidence. Missing terminal evidence leaves
started-process counts null with a lower bound. A helper attempt that fails
before creating a launch intent does not become a successful launch.

Scoped forced cleanup/group termination can be retained in public process or
cleanup receipts but never establishes DB read-close confirmation. An explicit
CONFIRMED close must be consistent with started=true, returncode0,
close_confirmed=true and no timeout/limit interruption. Cleanup cannot promote
an unconfirmed read to confirmed.

## Prefix and terminal analysis scope

Counts remain separate. If manifest-bound controller journal JSONL, terminal
view and counterpart scope are present, the module can recount stored ANALYSIS
events by sequence and expose their exact delta. This is stored-record indexing,
not controller replay or independent native validation. It does not assume that
the difference is always one. Without a sufficient basis, the crosswalk retains
UNRESOLVED_EVENT_DELTA and does not repair counters to match.

## Output and interpretation

New output contains `common/` with byte-exact supplied payloads and input
manifest; `OUTER_HANDOFF.json`, `OUTER_INDEX.json`, `OUTER_CROSSWALK.json`,
`OUTER_DENOMINATOR.json`, and a local output `MANIFEST.json`. No existing output
leaf can be reused. A partial failed write is retained; no retry is supplied.
The same outer snapshot/crosswalk is available to CPC_REFERENCE, B0 and B2.

`evidence_assessment=ASSESSABLE_STORED_RECEIPTS_ONLY` means the listed receipt
index has no detected missing mandatory members. It is not an execution,
authority, rights, scientific or UF5 PASS. Missing records produce
NOT_ASSESSABLE. A contradictory manifest/process identity is refused before
output. Parent/child exit states remain original, including failures.

Inner source-only branches and all original core/native decisions remain in the
byte-exact counterpart payloads. Inner offline computation flags are preserved
unchanged. The outer native evidence class and process receipts are additional
evidence, not a relabeling of engine computation or a stronger observer model.
No UF5 decision, inspector answer, learning/Y_next validity, mitigation of D2,
reader rights or JLA readiness is created.
