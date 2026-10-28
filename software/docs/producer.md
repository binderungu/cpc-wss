# WP05 offline capture/producer — source 1.4.1

Implements WSS V2 D05/R5–R6 and planWP05/Q07. This module creates local synthetic
mechanical evidence, not native/WSS usefulness or actual pedagogical approval.

## Inputs and trust

ProducerPolicy requires NEW externally supplied canonical profile bytes, total
(resource,config)→bundle map bytes, key registry, valid-from/expiry/configuration
UTC, full controller-context digest, and approved task ID/version. Frozen profile
must satisfy pinned CPC2.0.1 policy/source2.0.2; hint/answer and five configs map
to ten unique registered bundles. Five logical roles/keys remain distinct per
profile. Only SYNTHETIC_ONLY ASCII key material is accepted. Actual key bytes are
not saved by producer; only public key IDs/profile/map metadata are saved. This
is one-process fixture custody, not production security or independent roles.
Successful context snapshots retain exact configuration_time used to validate
the profile, controller_scope and the initial real/fault clock observation.
Configuration time must precede or equal every execution observation; a future
configuration timestamp is rejected before root creation/capture/publication.

The full controller.context.to_mapping() digest binds source epoch, actor/target,
item/type/digests and task/context-version declarations. Producer checks it and
task ID/version against separately supplied immutable renderer binding. This is
an explicit operator mapping, not equal-type comparison of unrelated version IDs,
and not evidence that any native context exists. Caller-created declarations,
matching hashes or frozen-state labels do not establish authority/rights.

Policy checks restricted profile via an explicitly verified bundled dependency
loaded into a private namespace from exact local source paths. A shadow global
cpc2 on sys.path is not imported/executed. Code executes only from the pinned
bundle after byte verification; no .pyc is written into source. This protects
ordinary origin selection, not a hostile Python interpreter/metapath/process.
All signed schema checks use the profile identifier bound. This producer needs
max_identifier_chars>=50 to fit its generated actual-generation capture refs;
otherwise a core-valid stricter profile is refused, not silently widened. Chain
byte/record/depth admission limits still belong to WP06; WP05 promises no ADMIT.

produce receives a WP03 controller/attempt, prospective resource/config, unused
local root, ProducerPolicy, signed raw resolution bytes, raw immutable prompt and
generation bytes, frozen CatalogSnapshot/ResolutionBinding, and optional LocalClock.
No root/path/input comes from a chain to grant itself trust. The supplied signed
resolution and launch assertion are schema/HMAC/context/window/namespace/link
checked, including active windows throughout execution. Upstream assignment
record and final outcome/full-chain admission are outside WP05. All checks refer
to supplied assertions and new labeled QA policy, never actual human permission.

## Capture and timing

capture_and_render saves raw prompt and generation transport before parsing;
normalizes Generation once, saves actual canonical object, and passes that same
Generation and prompt bytes directly to renderer. Snapshot readback verifies
persistence but is not the consumed-input source. Per-component capture/use
refs, body digest, catalog snapshot, trace and actual consume-completion clock
observation are retained. Failure leaves partial/raw files intact, not a false
usage proof. Only prompt/generation become measured entries; catalog/task/body
receipts do not promote six declarations or mitigate consistent false reporting.

LocalClock normally reads real datetime.now(UTC) with microseconds and
monotonic_ns, retaining local sequence. Fault reader is explicitly labeled
SYNTHETIC_FAULT_INJECTION and never represented as real-time success. Equal UTC
values are observed without correction; backwards UTC/monotonic values fail.
Valid-shaped backwards readings remain in failure clock history. No sleeping,
clock reset, skew tolerance or synthetic future release timestamp is used.

## One-call flow and publication

1. Allocate a caller-visible producer call_ref. WP03 then allocates/durably
   records invocation_ref before input preprocessing. If controller allocation
   or subsequent read is uncertain, return ALLOCATION_UNRESOLVED with known
   explicit local invocation ID when read-only reconciliation uniquely finds it;
   otherwise ID remains None. Pre-read failure returns ALLOCATION_NOT_STARTED.
   No native/nearest-time identity inference, write retry, new root or publication
   occurs. Caller must retain this returned receipt and reconcile the old journal;
   an unavailable ledger cannot guarantee every request was durably recorded.
2. Refused help remains PRECONDITION_REFUSED with received call accounted by WP03.
   Otherwise create a new exclusive local root/store and retain policy/context/
   raw resolution. Validate source/task/bundle/context/active windows, record
   CONSUME_STARTED, then capture/consume. Usage proof signs actual capture/use refs.
3. Stage body in snapshots (NOT release). Create/sign commitment at observed
   commit_time, fsync file+directory and read back, then observe durable completion
   separately. Record COMMIT_DURABLE only after it completes. Commitment contains
   no future release time. Recheck staged/commit bytes and active controller scope.
4. Designated publication is exclusive root/publications/response.txt. Set local
   state UNRESOLVED before possible visible writes. File write/fsync plus directory
   fsync completing establishes PUBLISHED. Subsequent readback/proof/controller or
   clock failures cannot erase that publication. Incomplete file/dir durability
   remains UNRESOLVED; partial bytes may be visible and are retained.
5. After actual boundary, observe release UTC/sequence. Enforce use<=commit<release
   and local sequence order plus active policy/resolution/launch windows. Sign
   release proof linking digest of FULL immutable signed commitment, then observe,
   create/sign/persist final exposure. Record-content digest excludes own integrity;
   proof-body digest and full-proof-object digest are distinct. Final exposure is
   after release, not falsely described as pre-release commitment.
6. COMPLETE requires all files/receipts and settled WP03 publication. INCOMPLETE
   retains publication state, optional exposure/failure refs and whether controller
   bookkeeping reconciled. If controller write is uncertain, do not retry/repair;
   root sidecar/returned publication can be PUBLISHED while controller count is
   unresolved. Downstream must reconcile and hold, never silently count zero.

Each call requires a new root. Existing root is never overwritten/deleted. There
is no write-resume API, rollback, automatic cleanup or retry of failed writes.
A distinct exclusive failure receipt may be attempted to record an error; this
is not repair/retry of the failed artifact. If that too fails, orphan bytes plus
returned result/controller journal remain explicit incomplete evidence. Exception
args/text/tracebacks are never copied; only closed safe codes/classes are retained.
Rootless failures carry a closed code in the controller evidence reference.

## Verification and limits

Test fixtures separately reconstruct bodies and HMACs from saved actual inputs
using stdlib, check temporal/event order, no release before durable commitment,
role/context/registry errors, strict profile bounds, shadow dependency, partial
writes/fsync, allocation uncertainty, and published-but-later-failed paths.
New fixtures/keys are not final WSS material/profile approval. No native/PHP/helper,
service/provider/model API, WP06 admission, outcome/baseline, scientific experiment
or manuscript edit. Four D2 negatives remain ADMIT/primaryJOINED/physicalMISMATCH,
both actual prompt and generation different from reported values; no archived
HMAC/core/join rerun. Y_next/JLA insufficiency unchanged; no G0 count/reset.

Persistence is cooperative POSIX single-coordinator local storage, not WORM,
transactional coupling across controller/store, power-loss survival, browser/
learner delivery prevention, distributed clock or malicious-observer security.
An abort observed before publication stops it; no atomic cross-thread/cross-process
native authorization guarantee is introduced. Same-process Python objects/clock
hooks are cooperative interfaces, not a trust separation against hostile code.
