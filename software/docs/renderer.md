# WP04: pure finite-catalog renderer, source 1.3.1

Implements WSS V2 D05/R1–R5, R7 mechanics; see the immutable design at
`outputs/CPC_JLA_WSS_DESIGN_CLOSURE_V2_20261016/03_RENDERER_CAPTURE_CONTRACT.md`.
This is a generic offline interface. Final WSS task/teaching content, review,
rights, actual profile/ten-bundle registry and worked execution remain pending.
No authored final content is installed. Test fixtures are explicit artificial
length/assembly data with padding; they are not pedagogical adequacy evidence.

## Explicit inputs

`Generation.from_mapping(...)` / `.from_bytes(...)` normalizes exactly four
typed fields to a frozen `Generation`. The only five accepted joint tuples are
G_BASE/G_STYLE/G_CAP/G_RATIONALE/G_SEED from V2. Booleans are not integers;
floats, unknown fields, duplicate JSON keys and other Cartesian tuples fail.
Transport whitespace is not part of this normalized consumed object; the
canonical UTF8 object bytes are its digest input, matching `cpc-json-v2` for
this supported scalar domain. No CPC module is called to render or normalize.

`CatalogSnapshot.from_bytes(raw)` requires canonical compact sorted-key UTF8
JSON with literal Unicode, no BOM/trailing whitespace/duplicate keys. It has
exactly `catalog_format="wss-renderer-catalog-v1"`, `catalog_version`,
`evidence_class`, `task`, and `conditions`. Evidence class is explicitly
SYNTHETIC_OFFLINE_FIXTURE or OWNER_SUPPLIED_CONTENT; neither asserts approval.
Task has the seven shared R1 fields other than format/resource/catalog version.
Conditions are exactly hint/answer and resources WSS-U01-HINT/WSS-U01-ANSWER.
Each condition has exactly `logical_resource_id` and `variants`; variants A/B
have directly the C/R/E string fields. All twelve slots validate together;
unselected bad content cannot become a silent partial catalog.

The sole template syntax is literal `{{task_span}}` replacement from the exact
parsed prompt. Each C template must contain at least one such token, so a
hard-coded span cannot stand in for that use path. R/E may also contain it.
Multiple occurrences are all replaced and counted. A span containing the token
is rejected to prevent ambiguous recursive expansion. All other braces/text
are literal data; there is no format/eval/HTML/shell execution. Bounds C280–360,
R160–200, E260–300 count Python Unicode code points after replacement, including
all exact newlines. A/B bound core bytes must differ. These are mechanical
domain checks; a human must still judge hint withholding and answer completeness.
Post-binding length is computed as template length plus token count multiplied
by the span/token length difference BEFORE allocating replacement output. This
rejects multiplicative expansion within the raw 1 MiB bound. The same bounded
binding helper is used at validation and consume; validated output slots never
allocate more than their C/R/E maxima during substitution.

Prompt is the supplied immutable canonical UTF8 `bytes`, with exactly the ten
nonempty string fields and format `wss-prompt-v2`. Catalog shared fields, exact
source excerpt/request, catalog version, task/version/span, resource/condition,
generation config and all expected digests must agree. Raw prompt bytes are
digested without a reserialization changing them. Input byte cap is 1 MiB per
prompt/catalog/generation transport; this is a local parser bound, not a new
CPC admission result. Mutable buffers are rejected; no filesystem path accepted.

`ResolutionBinding(...)` is a frozen, externally supplied context/assignment/
profile resolution: resolution/context/task/version/span/resource/condition/
config/bundle references plus exact catalog/prompt/generation digests and review/
internal-rights references. Unknown review/rights refs stay None and block render.
Non-null refs mean supplied declarations only. An arbitrary self-created binding
matching arbitrary digests cannot prove operator authority, content review,
rights, native context or signed profile validity. No automatic registry/profile
is fabricated. The caller must validate its actual trusted resolution outside
this module. Binding is not taken from untrusted prompt fields.

## Consume/assemble result

`render(prompt_bytes, generation, catalog, binding) -> RenderResult` accepts the
exact frozen local types. It keeps the same immutable prompt/generation/catalog/
binding instances used for parse/check/selection/assembly; no reread/copy of a
registry artifact is used as the consumed input. Prompt resource selects catalog
condition only after external-binding agreement; seed 0/1 selects A/B; requested
rationale is always included; compact omits E. Expanded adds whole E only if the
entire body fits cap. C then optional R then optional E use exactly two LF
characters as separators, no prefix/footer/fingerprint/version label. Never
truncate C/R, change condition/config or drop requested rationale to pass a cap.

Returns body UTF8 bytes and immutable trace with selected slots, lengths,
digests, version/bundle/task/source/context references and explicit elaboration
decision. Status is BODY_PREPARED_NOT_PUBLISHED. All four generation fields have
observable decision paths; differing bytes do not imply pedagogical effectiveness.
No test/renderer trace is a signed actual-use proof or secure observer.

Input/registry/content failures raise `ContractError` or its `RendererError`
subclass (which adds a local code), with no generic response, publication or core
verdict. WP03/caller must allocate invocation_ref before preprocessing/rendering,
then retain failure evidence. This module allocates no IDs and changes no
controller history. No invocation failure can be erased by a renderer success.

WP05 will implement actual captures/proof/sign/durable commitment/publication;
it must use the same consumed instances and handle partial captures/failures.
WP04 does not implement R6, perform core admission or emit external outcomes.
No native service, clock, environment/global input, file/network or process IO
is used. Imports have no IO side effects. Unicode normalization is not performed.

## Limits preserved

The planned measured components remain prompt and generation. Catalog/task/
output traces do not promote the six other CPC declarations to measured. The
four archived D2 counterexamples D3-00014/00029/00044/00059 remain ADMIT / primary
JOINED / physical MISMATCH, both actual prompt and generation different from
reported approved values. No mitigation or HMAC/core/join rerun is claimed.
Y_next NOT_MEASURED / NOT_VALIDATED_HERE; JLA scientific sufficiency unchanged.
