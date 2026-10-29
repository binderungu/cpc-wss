# SC01 source1.10.0 addendum (normative)

See sc01_response_scope.md: `courseid` stays positive context identity;
`feedback_route=ordinary_course` and explicit `response_scope_courseid=0`
bind the two response scope columns. `target_course_category` must be observed
positive and agree with both retained source-window metadata rows. `course` is
the ninth fixed InnoDB/SELECT table; category0/site Feedback is unsupported.
Wire1.0 and old controller/capture formats are not migrated. Current offline verification is external in
CPC_JLA_WSS_SC01_SEMANTIC_REPAIR_V1_20261020. No live readiness is established.

# WP02 restricted byte transport

`native_transport.py` is an IO-free Python companion to the PHP helper. It never
starts PHP, reads environment credentials, connects to a database, persists bytes
or acknowledges a workflow barrier. `NativeReadTransport.from_json(raw)` accepts
one bounded UTF8 JSON object with exactly transport_version, evidence_class,
receipt and blobs. Versions/classes are closed; JSON duplicate keys/floats and
noncanonical base64 fail closed. It returns immutable `NativeBlob` byte values
and an immutable WP01 `NativeReadReceipt`.

Limits:8MiB envelope,128 unique blobs,256KiB per blob,4MiB total decoded bytes.
Each blob ref is `blob:`+actual SHA256hex; sha256 field and exact byte_length must
agree. These names address local bytes, never native occurrences. Supplied item,
presentation and value refs must resolve to bytes matching any supplied paired
digest. A supplied snapshot_ref beginning `blob:` must resolve to its metadata
blob. Missing refs/digests remain partial observations and binding diagnostics;
external operator/provenance refs are not resolved or blessed as authority.
Unreferenced blobs remain retained for malformed/partial source evidence.

`to_mapping()` produces a fresh transport object. Neither content digest nor
syntactically valid MATCH_OBSERVED establishes that source access occurred.
Source actor/target/version conflicts are preserved; inspect receipt.binding_issues
separately. REPORTED_NATIVE_READ is a producer label, not an authenticity proof;
SYNTHETIC_OFFLINE_FIXTURE must remain visible on test data. Blob bytes may contain
raw native answers and belong in restricted sidecars, never normalized/public CPC
exports. Later WP03 must persist/verify snapshots before releasing any barrier;
this parser does not implement that integration or infer an approved scope.

Python synthetic tests only demonstrate this consumer's parsing/byte checks.
They are not execution tests of PHP, PDO, SQL semantics or the actual database.
The PHP access contract and pending native gate are documented separately.
