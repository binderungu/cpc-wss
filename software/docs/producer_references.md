# Prospective producer typed-reference index —1.9.0

This bounded offline repair addresses the seven unreferenced producer snapshots
observed by WP09. It changes no CPC wire/schema/rules, measured/declared boundary,
grading recipe, native helper or manuscript. Old source/data/results remain intact.

The previous producer saved profile/map/resolution/context, usage/release proof
and the complete manifest without retaining their returned SnapshotReference in
the downstream graph. All bytes existed; filename hashes cannot recover opaque
reference IDs. It is not valid to guess those IDs or relabel old files to close
the archived gap. The old reports retain their original diagnostic state.

The new producer creates an IndexedSnapshotStore and a sibling `reference-index/`
before the first snapshot. All ordinary SnapshotStore.put paths, including the
unchanged capture_and_render/save functions, route through this store. A put
persists the original bytes, then records the exact returned reference in an
append-only typed journal with call/invocation/store identity and readback,
then returns to its caller. Input object identity, consume semantics, signatures,
commit/release timing and published response bytes are not replaced by the index.

The index contains only opaque typed references and scope metadata, not raw
payloads or key material. Its own files are outside the snapshot payload store,
so the complete-manifest reference can be indexed without a self-reference
cycle or another unreferenced snapshot. Existing ledger and snapshot encodings
are unchanged. Imports are inert; creation/read/write require explicit calls.

ProducerReferenceIndex.create requires an empty unbound indexed store and a new
fixed sibling directory. It cannot backfill an existing nonempty store. There
is no writable-open/recovery/migration API. Callers must not bypass the indexed
put with a base-class call or modify private fields; such cooperative control
limits are explicit, not a hostile-process/independent-custody guarantee.

Open_readonly and reporting.capture_producer_inventory require the **actual
caller-known invocation_ref and call_ref**, e.g. from ProductionResult, rather
than self-authorizing those values from index metadata. They check closed
metadata/record shapes, ledger scope/hash chain, uniqueness, store/owner identity
and exact referenced bytes. The explicit reader follows no arbitrary payload
reference shapes and does not inspect filenames to invent IDs. A legacy root
without an index fails as unavailable, never as an empty/complete index.

Successful puts are registered before use. There is deliberately no atomic
transaction between snapshot and journal. If an exception/crash occurs between
them, bytes remain and may be a genuine orphan. Index append uncertainty poisons
future writes; producer returns INCOMPLETE, not COMPLETE. A post-publication
failure retains PUBLISHED and the controller publication count; no cleanup,
rollback, retry, score change or zero-exposure inference is performed. Ordinary
parse/signing failures can still retain a successfully indexed failure receipt.

The reader rejects missing/corrupt/truncated/nonregular/foreign index data.
An extra unindexed file is listed as ORPHAN and producer inventory.complete is
false. Generic inventory semantics for other stores remain unchanged. An index
receipt proves only declared snapshot-reference integrity; it does not by itself
establish a successful workflow, native truth, owner authority or release rights.

Supported index bounds are10000 references and64MiB total referenced bytes;
the original per-snapshot16MiB bound applies. Tests include capacity refusal and
partial files, not performance/latency/power-loss qualification. Locks and hashes
are local cooperative controls, not WORM or a distributed transaction.

New verification includes actual synthetic positive and two-publication hold
workflows. Every producer root has its own prospective index, actual captures
are common to CPC/B0/B2, and all declared roots are inventoried. Zero orphans may
close this reference-accounting gap in the new declared scope; it does not
mitigate the four D2 counterexamples, close UF1–UF6, or establish JLA sufficiency.
Y_next remains NOT_MEASURED/NOT_VALIDATED_HERE. No Moodle/LIRA/DB/provider,
native checkpoint, scientific experiment, manuscript, WP10 or public release.
