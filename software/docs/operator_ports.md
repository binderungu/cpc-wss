# Supplied local operator metadata ports — source 1.12.0

`SuppliedOperatorPorts` connects externally supplied current policy/materials to
the existing worked runner. It does not access Moodle, open a DB/HTTP connection,
launch a process, create a profile/key, approve rights, or infer human consent.
The inherited key/profile contract accepts `SYNTHETIC_ONLY_` material; these are
local demonstration assertions with one operator trust boundary, not production
attestation or mitigation of the historical four D2 counterexamples.

## API

```python
from wss_bridge.operator_ports import SuppliedOperatorPorts

operator = SuppliedOperatorPorts(
    policy, context, catalog,
    prompts_by_condition, generations_by_config, recipe,
    content_review_ref, internal_rights_ref,
    consent_declaration, eligibility_declaration,
    operation_port,
)
ports = operator.ports
```

Required supplied values:

- A typed current `ProducerPolicy` containing canonical frozen profile/bundle-map
  bytes, five local key roles, validity period, configuration time and exact
  controller-context digest. The module creates none of these and never exports
  its key registry. Profile/key validation is inherited and version-pinned.
- A typed ready `ControllerContext` and exact `CatalogSnapshot`; the catalog task
  identity/version and context task-version reference must match policy.
- Exactly two canonical immutable prompt byte objects, keyed `hint`/`answer`, and
  five canonical immutable normalized generation objects keyed
  `G_BASE/G_STYLE/G_CAP/G_RATIONALE/G_SEED`. Every one of the ten registry vectors
  must match its supplied prompt and generation. The six other component modes
  remain declared according to the inherited profile; no new measurement claim
  is created by this module.
- A typed `OutcomeRecipe` bound to the exact context follow-up item/presentation,
  task version, supplied content-review reference and internal-rights reference.
  Nonempty references are declarations; this module cannot verify owner rights
  or external review. No placeholder is silently invented or substituted.
- `consent_declaration` with exactly `state`, RFC3339 `at`, `authority_ref`, and
  `policy_version`. The authority/policy must be permitted by the supplied
  profile; timestamps may not be in the future. `eligibility_declaration` must be
  an explicit bool. A declaration of consent is not evidence of human consent.
  In a synthetic no-human demonstration the owner must accurately identify the
  synthetic declaration rather than implying participants were enrolled.
- An explicit operation callable, such as `FileOperationPort`, supplied by the
  controller/operator. The module does not perform source acquisition itself.

Optional `clock` must be an exact `LocalClock` with `source=REAL_UTC` and the
profile clock ID. Otherwise a real UTC/monotonic `LocalClock` is constructed.
The policy is checked against current observations on construction, each help
preparation, outcome signing, and admission context supply. No historical or
future timestamps are manufactured to fit the window.

## Help metadata

`help_inputs(HelpRequest)` checks the exact context, attempt assignment and
publication ordinal. The caller's invocation has already been allocated by the
runner. Assignment/launch/resolution records use current UTC and unique local
IDs; assignment digest links both launch and resolution, and resolution names
the approved resource/config/bundle. Signed records/proofs are checked with the
existing pinned schema. Prompt/generation/catalog bytes remain the exact objects
supplied to the port and later consumed by the inherited producer.

Namespace claims are deterministically selected from the supplied profile's
mapping for the prospectively assigned condition. They are local policy claims,
not independent observations of physical delivery. Required authoritative maps
must support the condition. A repeated invocation, out-of-order publication,
changed assignment within an attempt, or more than 96 issued help records is
refused. The limit is inherited artifact capacity, not an execution grant.

The resulting `HelpInputs` carries the same current clock to the producer, which
performs actual local consume/capture, commitment and durable-file publication
under its existing checks. Calling `help_inputs` alone does not publish help.

## Outcome metadata and admission

`sign_outcome(OutcomeRequest)` accepts only the exact assignment/resolution it
previously issued for that episode/attempt/resource/config. It validates the
supplied signed exposure's schema, HMAC, context, resolution predecessor,
invocation, condition, bundle and timing. The seven-field derived composite must
match the exact exposure, experiment/attempt and requested permitted purpose.
Only the supplied derived `outcome_key` enters CPC outcome metadata; no scalar
value/score is placed on that wire. Each key is signed once per port instance.
Cross-exposure/source-key ownership remains the shared OutcomeStore's job.

The fixed first selected source, first prospective serialization owner and E3
two-publication HOLD policy remain inherited runner/controller behavior. The
ports never clone an outcome, choose the highest score, rewrite an export, or
replace a core verdict. Actual core evaluation is still performed by the pinned
CPC adapter and independent-rules comparison.

`admission_context()` supplies the same profile/key registry and a current
validation time. Existing context receipts serialize key fingerprints, not key
material. These declarations do not grant native access, scientific approval,
public release or submission permission.

## Qualification boundary

Targeted tests are under
`outputs/CPC_JLA_COMPLETION_CAMPAIGN_V1_20261026/qualification/operator_ports/`.
They use inherited artificial padding/wire fixtures only and preserve their own
partial/completed outputs in that new tree. A full three-episode synthetic
integration exercises actual pinned core and baseline evaluation, no-clone E3,
and metadata links. It is software QA, not the pedagogical worked demonstration
or a native observation. No production module imports a fixture factory.

The inherited pinned schema/reference loader may read its verified bundled
reference sources; it never selects a user-named plugin or external module.

Attempt001 failed before runner-root creation because the test harness selected
a symlinked macOS temporary directory; its log is retained. The harness now uses
a resolved new workspace directory. No storage guard or inherited source was
weakened. Current source-level qualification does not erase historical native
driver exit1 or prove current source truth, educational validity, usefulness,
UF5, or JLA readiness.
