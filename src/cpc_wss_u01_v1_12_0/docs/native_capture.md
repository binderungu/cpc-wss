# SC01 source1.10.0 addendum (normative)

See sc01_response_scope.md: `courseid` stays positive context identity;
`feedback_route=ordinary_course` and explicit `response_scope_courseid=0`
bind the two response scope columns. `target_course_category` must be observed
positive and agree with both retained source-window metadata rows. `course` is
the ninth fixed InnoDB/SELECT table; category0/site Feedback is unsupported.
Wire1.0 and old controller/capture formats are not migrated. Current offline verification is external in
CPC_JLA_WSS_SC01_SEMANTIC_REPAIR_V1_20261020. No live readiness is established.

# WP03 supplied capture preservation

`native_capture.py` imports inertly. It never starts PHP, queries a native source,
creates native IDs, or grants access. Its three explicit APIs are:

- `persist_raw(raw: bytes, store: SnapshotStore) -> SnapshotReference`: preserves
  exact raw bytes before parsing, including invalid transport up to WP01's finite
  snapshot bound. A storage content address is never a native identity.
- `check_and_store_capture(raw_reference, store) -> CaptureBundle`: reads raw,
  parses bounded WP02 transport, preserves **every** blob, records closed manifest,
  and reads the closure back before returning. Invalid transport raises
  `ContractError`; raw remains. Semantic metadata defects return flags and retain
  decoded blobs. Caller must retain the ingestion/failure and raw reference.
- `load_capture(manifest_reference, store) -> CaptureBundle`: read-only closure
  verification; missing/corrupt references fail, without repair or write.

Frozen `CaptureBundle` has `transport`, `raw_reference`, ordered tuple
`blob_references`, `manifest_reference`, and tuple `metadata_issues`. There is no
authority or native verification field. Empty metadata issues means only internal
metadata coherence; controller separately compares trusted context, operation,
source epoch, actor, target, cursor and binding diagnostics.

Manifest format `wss-native-capture-v2` is a **closed** JSON object with exactly
`format`, `raw_reference`, `blob_references`, `metadata_issues`. It uses existing
`wss-workflow-json-v1` canonical encoding. Every reference has WP01's four closed
fields `store_ref`, `snapshot_ref`, `sha256`, `byte_length`. Reopening checks raw,
all blob bytes, ordered references, recomputed issues, address and canonical
manifest bytes. Raw and manifest local names are `capture-raw:<sha256hex>` and
`capture-manifest:<sha256hex>`; helper blob names remain `blob:<sha256hex>`.

Singleton matching packets must contain the helper's closed snapshot metadata:
`standard_log_record_id`, `raw_other_ref`, `native_snapshot_fields`, and
`source_projection_details`. Snapshot projection equals the complete supplied
receipt snapshot with `snapshot_ref: null`, including strict scalar types. The
positive native log ID equals the sole occurrence. Source details have exactly
**five** keys: `tmp_completed`, `raw_item_type_ref`, `item_byte_length`,
`presentation_byte_length`, `value_byte_length`. This fifth-key clarification is
derived from unchanged helper `finish_snapshot` call at lines 625–630. Temporary
completion is integer zero; byte lengths match preserved blobs; raw item type
resolves to nonempty UTF8 equal to the receipt field. Empty value bytes are valid.

Exactly one event metadata blob has closed keys `native_occurrence`,
`raw_other_ref`, `raw_text_column_refs`, `raw_other_byte_length`. Its occurrence
equals the supplied receipt exactly; same raw-other ref resolves and length
matches. Closed text-ref object has `eventname`, `objecttable`, `origin`; each
resolves to nonempty UTF8 bytes equal to the corresponding supplied event field.
Arbitrary source blobs are retained, never evaluated/deserialized as code. Raw
Moodle `other` is opaque here, including serialized bytes; WP02's source decoder
is not rerun or replaced. Unknown duplicate metadata shapes fail coherence.

Partial/multiple/unavailable packets remain preserved, with
`CAPTURE_STATUS_NOT_MATCH`, `CAPTURE_OCCURRENCE_NOT_SINGLETON`,
`CAPTURE_SNAPSHOT_NOT_SINGLETON`, or `CAPTURE_METADATA_INCOHERENT` as applicable.
They cannot satisfy the controller anchor barrier. Metadata coherence does not
authenticate a producer: a consistent lying producer can fabricate it all. The
four D2 counterexamples remain ADMIT / primary JOINED / physical MISMATCH, with
actual prompt and generation differing from approved/reported values; this code
does not mitigate them.

Writes use WP01 exclusive immutable-name storage. Existing names are reused only
after `get` verifies the expected length/hash and exact bytes. Failed writes may
leave orphans; no deletion, truncation, overwriting, hidden retry or recovery is
performed. The controller supplies a cooperative command lock. These are separate
multi-file IO steps, not an atomic transaction, WORM or hostile-filesystem proof.
One private coupling reads pinned `SnapshotStore._store_ref` solely to construct
expected references for verified reuse; WP01 source/API stays unchanged. Its
normal `get` still verifies the store metadata, reference and bytes.

Tests use prior actual-PHP **SYNTHETIC_OFFLINE_FIXTURE** wire output only. They
do not access Moodle/LIRA or establish native qualification, rights, source truth,
learning effects, or JLA readiness. Execution results belong to the new root
verification report, not this source design description.

## SC01 window coherence on every status
Both source-window singleton rows must carry a positive category and the same positive context courseid/cmid as the receipt target, for NO_MATCH/partial as well as matched records. Missing/site/wrong-context metadata produces CAPTURE_METADATA_INCOHERENT and cannot pass the controller WAIT allowlist. All raw bytes remain retained. Source-int normalization matches canonical PDO numeric strings only; typed record values never coerce bool/string/float IDs.
