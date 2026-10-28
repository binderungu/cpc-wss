# CPC normative contract 2.0.1

Date: 13 October 2026. Document ID: CPC-CONTRACT-2.0.1-20261013.
Status: **NORMATIVE_SPECIFICATION — D1_REVERIFICATION_PENDING**.

This is the prospective normative specification for a new synthetic, local condition-attribution admission release. It clarifies JSON depth in a new contract version; it does not rewrite contract 2.0.0, its implementation, frozen oracles, failed/corrected D1 runs, earlier results or the manuscript. MUST/MUST NOT prescribe requirements, not evidence that they execute correctly. The new contract, implementation, profiles, registry and oracle must be frozen before their new D1 run. Contract review is not scientific DESIGN_PASS or submission authority.

## 1. Normative precedence and evaluated boundary

This document is authoritative for contract 2.0.1. FIELD_REQUIREMENTS.json and RULE_DECISION_MATRIX.csv are structured specifications of its fields and decisions; a discrepancy among them blocks implementation until resolved in a new document revision. No historical JSON schema is normative for 2.0.1. Future executable schemas MUST implement the same wire language.

The profile is supplied separately by the admission operator and MUST be immutable/versioned before execution; it MUST NOT be accepted from an untrusted chain as its own trust root. Admission means only that one chain meets the specified attribution evidence. There are four logical record classes: assignment, resolution, exposure and outcome. Launch, commitment, usage and release attestations are nested proofs, not additional experimental observations or learners.

Scope is one chain and its exported attribution record. Database-wide outcome uniqueness, exactly-once delivery, global nonce replay, learning effects, usability, production keys, real LTI compatibility, distributed-clock trust and truth of a colluding set of issuers are outside this contract's evaluated claim. A future local prototype MUST describe its actual trust/clock assumptions. A signed assertion is not proof of truth or artifact use by itself.

The planned strong profile requires measured prompt-template and generation/response-configuration artifacts. Remaining components are declared, explicitly labelled as such. No claim that the entire AI stack is measured follows. A declared-only profile may be defined separately but MUST NOT satisfy the strong profile or inherit its actual-use claim.

## 2. Wire input and output

`records` MUST be an array of record objects, not null/a scalar/map. An empty array represents absent evidence (QUARANTINE unless a stronger rule exists); a nonobject member is ERROR_INPUT. All available supported objects are retained for safe partial evaluation. The prototype input bounds are 1 MiB raw UTF-8, at most 16 records, JSON depth at most 32 as defined in section 2.1, and identifier strings at most 256 Unicode characters. Operator-configured limits may be stricter but are frozen before invocation; exceeding them is ERROR_INPUT with no truncated silent admission. These are supported-domain design bounds, not measured capacity/security results.

Input is a UTF-8 JSON object with exactly `contract_version`, `profile_id`, `profile_version`, `case_id` and `records`. The root is unsigned routing/accounting metadata; root extensions are not supported. Its contract/profile fields must match the signed fields in every available supported record/proof. `contract_version` MUST equal `2.0.1`; identifiers MUST be nonempty, non-whitespace strings with no surrounding whitespace or control characters. No legacy generator fields such as seed, replicate, ground_truth_valid or fault labels belong in this admission interface. They may exist in a separate test manifest and MUST NOT influence admission.

JSON MUST reject duplicate object keys, NaN/Infinity, invalid UTF-8 and nonobject roots. The supported representation uses strings, booleans, null, arrays/objects and nonnegative integer event sequences; floating-point values are not accepted in signed evidence. Booleans MUST NOT count as integers. Timestamps MUST be RFC3339 instants with explicit timezone; future parsers MUST reject timezone-naive or unrepresentable instants without uncontrolled exceptions.

Every received input gets an operator-assigned `input_ref` and raw-byte `input_sha256` before semantic evaluation. Do not rely on readable case_id for accounting. Output MUST include `input_ref`, `input_sha256`, `case_id` (null if unavailable), contract/profile versions, final disposition, rule-addressed diagnostics and `admitted_record` (null unless ADMIT). Raw input MUST NOT be placed in diagnostics or normalized export.

Normalized admitted export MUST contain only input_ref, case_id, experiment ID/version, opaque unit token, attributed condition, artifact bundle version, exposure record ID/digest, outcome_key and permitted purpose. Outcome values, learner content and direct identities MUST NOT be included. Export MUST NOT begin until the admitted record is complete and checked. Unknown inputs and refusal/error rows MUST still appear in the exclusion ledger.

All objects are closed-field by default. `extensions` is an optional container only within a signed record or signed proof body; it contains namespaced keys registered in the external profile and is covered by that record/body integrity. It is forbidden at the unsigned chain root or outside a signed body. V2 permits only metadata extensions that neither redefine nor satisfy required fields, authority, timing, artifacts, integrity or eligibility. Unknown keys outside that container or unregistered extension keys are ERROR_INPUT; policy-forbidden identity/content fields are REJECT when detectable from parsed evidence. Record order does not change a decision. Unknown record_type is ERROR_INPUT, not silently ignored.

### 2.1. JSON depth: root-zero, including keys and scalar leaves

Depth is defined on the **complete successfully decoded JSON value**, before structural, semantic or cryptographic evaluation. The decoded chain root is at depth **0**. Traversing from an object to each of its property keys or property values adds **1**; traversing from an array to each item adds **1**. A key and its value are sibling children of their object, not a key-to-value path. Object keys are scalar string children. Scalar leaves and empty arrays/objects count at their own depth. The chain depth is the greatest such depth, including the root itself.

For a decoded value `v`, define `D(v)` recursively:

- Scalar (`null`, boolean, number or string): `D(v) = 0`.
- Array: `D(v) = max({0} union {1 + D(item) : item in v})`.
- Object: `D(v) = max({0} union {1 : key in v} union {1 + D(value) : (key, value) in v})`.

Thus an empty container has depth 0, and a nonempty object has depth at least 1 because its keys count. String length, UTF-8 byte length, characters inside a string, key spelling and JSON whitespace do not add depth. Escaped textual JSON inside a string remains a scalar; it is not recursively decoded for this bound. Unsupported numbers or a scalar chain root may have a defined depth but still fail the other wire requirements under I01.

| Decoded JSON | Depth |
|---|---:|
| `{}` | 0 |
| `[]` | 0 |
| `null` | 0 (unsupported chain root) |
| `{"k": {}}` | 1 |
| `{"k": {"z": []}}` | 2 |
| `[null]` | 1 |
| `{"k": [null]}` | 2 |

The bound covers the **entire decoded chain**, including all records, payloads, nested proof bodies, integrity objects, signed extensions, unknown fields and unsupported subtrees. It does not cover the externally supplied operator profile, separate key registry, validation time or test manifest: those are separately validated/configured invocation inputs, not descendants of the decoded chain root. Removing integrity, proofs, extensions or unsupported subtrees before measuring depth is forbidden.

The frozen profile's `input_limits.max_depth` MUST be an integer from **1 through 32 inclusive**, with booleans excluded. A stricter limit is valid configuration even if too small for a complete four-record chain; it MUST NOT be raised automatically. `D(chain) <= max_depth` passes **only the depth guard**; it cannot establish structural validity or ADMIT. `D(chain) > max_depth` MUST terminate input evaluation with **I01 / ERROR_INPUT before structural, semantic or cryptographic checks**, retain input accounting, and produce no admitted export. No partial/truncated subtree may be admitted. The ordinary rule precedence for safely evaluated in-domain input remains unchanged; an over-depth input does not undergo partial semantic evaluation that could override its I01 verdict. Invalid external configuration is still checked first and produces ERROR_CONFIG separately.

## 3. Common record envelope and integrity

Every record requires: record_id, record_type, contract_version, profile_id, profile_version, schema_version, experiment_id, experiment_version, unit_token, issuer, audience, deployment_id, context_id, issued_at, valid_from, expires_at, nonce, predecessor_record_id, predecessor_digest, payload and integrity. Optional extensions obey section 2.

- Signed contract_version MUST equal `2.0.1`; signed profile_id/version MUST match the externally frozen profile and top-level chain. `schema_version` MUST equal `cpc-2.0.1`. All nested proof bodies also require these three signed contract/profile fields.
- All identifiers above are nonempty strings. The unit token is opaque and MUST NOT be a student number, email or direct identifier. Each record_id and envelope nonce MUST be unique within this chain; global uniqueness is not claimed.
- record_type is one of the four logical classes. The profile specifies the authorized issuer, audience, key policy, deployment and context for each class. Equality to the profile, not mere mutual equality among records, is required.
- For assignment, both predecessor fields are null. For resolution/exposure/outcome they are nonempty record ID and digest pointing respectively to assignment/resolution/exposure. predecessor_digest is the predecessor record integrity.content_digest (not a full-file or proof-object digest). Nested proof_ids MUST be unique within their chain; the future evaluator must report reuse/contradiction, without claiming cross-database replay prevention. Every available predecessor relation MUST be checked even when a later record is missing. There is no fallback-to-null comparison proving a relation.
- `valid_from <= issued_at < expires_at`, `issued_at <= validation_time`, and `valid_from <= validation_time < expires_at` MUST hold. No clock-skew tolerance is admitted in this local prototype. validation_time and profile identity are trusted invocation context captured by the operator, not supplied by the input. Frozen replay time is permitted only in explicitly labelled synthetic reproduction and MUST NOT be presented as current live admission.
- Hashes are `sha256:` followed by 64 lowercase hexadecimal digits. Integrity requires algorithm, key_id, content_digest and mac. The prototype algorithm is HMAC-SHA256 with fixture-only key custody; algorithm is exact, key_id is a profile-authorized nonempty ASCII string, mac is `hmac-sha256:` plus 64 lowercase hexadecimal digits. Unknown authorized-key relationships or a well-formed invalid MAC/digest are REJECT; missing/malformed envelopes are ERROR_INPUT.
- Canonicalization is `cpc-json-v2`: recursively sorted string keys, compact JSON separators, Unicode unescaped, UTF-8, no floats/nonfinite numbers or duplicate keys. Record digest excludes its own top-level integrity and covers all other fields including nested proofs and extensions. HMAC signs the ASCII digest string. Every nested proof is exactly an object with body and integrity. Each body requires signed contract_version, profile_id, profile_version, experiment_id, experiment_version, unit_token, audience, deployment_id, context_id, valid_from and expires_at as well as its proof-specific fields. All must match the chain/profile and bound record context. Every proof must satisfy valid_from <= issued_at < expires_at, issued_at <= validation_time, and valid_from <= validation_time < expires_at. Its integrity.content_digest is SHA256(cpc-json-v2(body)), and its MAC signs that ASCII content digest. For release_attestation.commitment_digest, use SHA256(cpc-json-v2(the complete immutable commitment object, including body and integrity)). Record predecessor pointers use predecessor.integrity.content_digest; these three digest meanings are distinct and have no self-reference. Proof body extensions are optional only under the signed, registered-metadata policy above.

A separate profile key registry is required for fixture reproduction. Fixed public SYNTHETIC_ONLY keys MUST NOT be represented as deployment credentials/security. Bytes-consistent hashes are not truth, secrecy or ethical authorization.

## 4. Required payloads

Presence, type and semantic validity are separate requirements. Absence/null/wrong type of a required payload field is ERROR_INPUT. Empty values in fields that require nonempty identifiers are ERROR_INPUT. A well-typed value outside an explicitly authorized domain or a contradictory relationship is REJECT. Entirely absent required record classes are evidence incompleteness and may be QUARANTINE. See section 8 for precedence and independently decidable contradictions.

### Assignment

Requires assigned_condition, assignment_policy_version, scope, resource_id and launch_nonce. Each is nonempty string. assigned_condition MUST belong to profile.conditions; assignment_policy_version and scope MUST equal approved profile values; resource_id MUST exist in profile.resource_condition_map and map to the assigned condition. The launch_nonce is a separate required invocation binding, not replaceable by an envelope nonce.

### Resolution

Requires requested_condition, resolved_condition, claim_namespaces, resolver_version, fallback_used, fallback_authorized, authorization_ref, launch_nonce and launch_attestation.

Conditions/resolver_version/launch_nonce are nonempty strings; namespace object is nonempty and contains exactly the required authoritative/consistency namespaces plus explicitly allowed descriptive namespaces configured by the profile. Every value is a nonempty string. fallback fields are booleans. When fallback_used is false, fallback_authorized MUST be false and authorization_ref null. When true, fallback_authorized MUST be true and authorization_ref a nonempty ID of an externally registered permission. V2 permits same-condition fallback only, to an approved artifact bundle; no silent condition reassignment is allowed. A future reassignment design requires a separate contract version.

launch_attestation is a signed proof from the profile's assignment/launch authority, not merely a resolver-signed restatement. Its body requires proof_id, issuer, issued_at, experiment_id/version, unit_token, audience, deployment_id, context_id, assignment_record_id/digest, resource_id, launch_nonce and namespace_values. Its integral proof body and signature MUST be verified under launch-authority key policy. All context/assignment/resource/nonce relations MUST match the assignment and resolution. The resolver's claim_namespaces MUST equal the attested namespace_values before translation.

For each required authoritative or consistency namespace, the external profile supplies a total permitted raw_value→condition mapping. All required mapped values MUST agree and equal requested_condition, assigned_condition and resolved_condition. Missing mandatory namespace is ERROR_INPUT; unknown namespace/raw value, unauthorized mapping version, conflicting mapped values or coherent-but-wrong mapped condition is REJECT. Descriptive namespaces are labelled nonauthoritative and cannot influence resolution or satisfy authority requirements. Profile.resolver_version and mapping_version are fixed; the signed launch proof's resource identity is the anchor, not an activity title or display label.

This CPC fixture proof is not asserted to be a standards-compliant LTI token. Real LTI signature/claim transport requires a separately evaluated adapter.

### Exposure: a two-phase receipt within one logical record

Requires enacted_condition, artifact_version, artifacts, invocation_id, commitment and release_attestation. Condition/bundle/invocation IDs are nonempty; artifacts MUST be an object map from component_id to an object with exactly version, digest and evidence_mode. The keys are exactly the registered component set (eight for the planned strong profile). Missing keys/entry fields, unsupported types, unknown keys or duplicate JSON keys are ERROR_INPUT; well-typed unapproved version/digest/mode relationships are REJECT. Evidence mode is exactly `measured` or `declared` and MUST match the profile policy. The strong profile requires measured `prompt` and `generation`; other components remain declared. Supplied vector MUST match the approved registry selection, but registry equality alone is insufficient for measured entries.

**Commitment** is created, signed and durably persisted before release. Its body requires proof_id, issuer, issued_at (=commit_time), clock_id, sequence, experiment_id/version, unit_token, resolution_record_id/digest, invocation_id, enacted_condition, artifact_version, artifacts and usage_attestation. Its integrity must be under the authorized runtime key. Body links must match the exposure and the resolution. It MUST NOT contain an unknown future actual release timestamp. A planned release timestamp is neither a substitute for observed release nor accepted as measured proof.

**Usage attestation** is a local observer proof containing proof_id, issuer, issued_at (=use_time), clock_id, sequence, invocation_id, resolution_record_id/digest and measured_components. measured_components MUST be an object map whose keys are exactly the profile required_measured_components (`prompt` and `generation` for the strong profile), not an array. Each value is an object with exactly component_id, version, digest, capture_ref and use_ref; all identifiers are nonempty. Missing required component keys/entry fields or unknown keys/types are ERROR_INPUT; duplicate JSON keys fail decoding. A well-typed component_id differing from its map key is REJECT. Thus each required component occurs once, without a first-entry selection policy. It attests bytes/objects actually consumed to form the invocation's response, not merely bytes re-read from a pathname later or a configured registry value. Observer key/role MUST be authorized separately by the profile. Distinct logical key IDs are required; the prototype may still be one instrumented process and MUST disclose that limitation.

For measured entries, digest MUST be recomputed by the capture mechanism from the actual immutable bytes/objects consumed. The future capture/observer implementation, not the offline validator, supplies the truth of that measurement; D2 must independently inspect this path and artifact-substitution controls. Raw bytes or filesystem paths MUST NOT be stored in the contract. Fixture `prompt` uses raw bytes; fixture `generation` uses cpc-json-v2 over the object actually consumed. version/digest MUST match both usage proof and approved registry. Missing measurement proof in a structurally complete, declared-only entry cannot satisfy a measured requirement and is REJECT. Malformed/missing required proof fields are ERROR_INPUT.

**Release attestation** is created after the actual local release boundary by the authorized observer, and requires proof_id, issuer, issued_at (=release_time), clock_id, sequence, invocation_id, commitment_digest, exposure_record_id and release_boundary. The boundary in the synthetic profile is `durable_local_response_file`; it proves no browser/network/learner receipt. The commitment digest is computed from the immutable signed commitment; no retroactive rewriting of that commitment is allowed. Final exposure record may be assembled/signed after release, containing both prior commitment and later release proof. Its record digest then provides outcome linkage; it is not falsely called pre-release itself.

UTC instants MUST satisfy `consent_at <= use_time`, `resolution.issued_at <= use_time <= commit_time < release_time <= exposure.issued_at <= outcome.issued_at <= validation_time`. Local observer clock_id MUST match the profile and the two proof clocks; observer/runtime event sequences MUST satisfy `use_sequence <= commit_sequence < release_sequence`. Sequence values are nonnegative integers, not booleans. UTC order and local observed order are both required for this prototype. Unknown/untrusted clock contexts are REJECT; unavailable required observation fields are ERROR_INPUT. Distributed clocks, streaming/network release, secure enclaves and adversarial observers are outside this prototype claim.

### Outcome

Requires exposure_record_id, exposure_digest, attributed_condition, outcome_key, consent_state, consent_at, consent_authority_ref, consent_policy_version, purpose and eligible.

IDs/key/policy/purpose are nonempty strings. outcome_key is opaque metadata naming one governed outcome, not its value. Exposure ID/digest MUST match the final signed exposure; attributed_condition MUST equal all four-layer condition values. consent_state is consented/declined/withdrawn/unknown; only consented with eligible=true may admit. eligible is a boolean. consent_policy_version and consent_authority_ref MUST match externally approved profile entries and permitted purpose. These checks establish consistency of an authority assertion, not legal ethics approval, real consent collection or production governance. Declined/withdrawn/unknown/ineligible or unpermitted purpose is REJECT. consent_at is an explicit-zone timestamp and must meet the prospective timing above.

## 5. Profile and registry contract

A normative profile requires profile_id/version, contract_version, schema_version, experiment_id/version, approved conditions, expected audience/deployment/context/scope, resource_condition_map, approved assignment policy/resolver/mapping versions, namespace policy, issuer/key role policy, permitted purposes, approved consent references/policy, artifact registry, required measured components, component canonicalizations, allowed same-condition fallback permissions, observer clock and release boundary, extension allowlist and privacy denylist.

Registry versions and digests MUST be actual frozen component metadata before execution, not invented filename hashes. The historical stage 1 policy did not populate digests or executable schemas. PROFILE_POLICY_2.0.1.json is the new design policy, not a trust-root instance. This release must materialize and freeze separately supplied version 2.0.1 profiles, actual component metadata and synthetic-only key registries before new D1 execution. Its frozen max_depth follows section 2.1; stricter positive limits are permitted even when no complete chain can fit. An absent/inconsistent operator profile is `ERROR_CONFIG`; no chain is evaluated/admitted under it. ERROR_CONFIG is distinct from an input verdict and blocks the entire affected run. Input rows already received must remain accounted as NOT_EVALUATED_CONFIG in the run ledger.

Two design profiles preserve meaningful differences: writing feedback uses authoritative raw `guided/plain` mapped identically; quiz tutoring uses raw `Q_HINT/Q_ANSWER` mapped to `hint/answer`. Each resource has an externally fixed condition. The second profile thus tests translation policy, not merely a new title. Optional descriptive `ui.activity_title` is excluded from condition derivation. Actual authority values, permitted references, artifact bytes/digests and executable configs must be materialized/frozen before D1/D2. No old August protocol ID/freeze timestamp can identify a new October contract/profile.

## 6. Cross-record cardinality, linkage and order

Exactly one assignment/resolution/exposure/outcome is required to admit. Missing any class is QUARANTINE if no stronger independently decidable defect exists. Multiple assignment/resolution/exposure records are contradictory and REJECT. Multiple outcome records are QUARANTINE as ambiguous attribution unless an independently established contradiction exists; duplicates are never silently selected. Duplicate record IDs or envelope nonces within a chain are REJECT even when the outcome count is ambiguous.

All available records/proofs must share experiment ID/version, unit, deployment/context/audience and authorized role/profile identity. All five condition values must match authorized, resource-bound derivation. Outcome reference/digest and the exposure predecessor link are separate relations that both must be checked. Conditions are domain strings supplied by the frozen profile, never hardcoded A/B/C/D across all profiles.

Envelope issuance is monotonic assignment <= resolution <= exposure <= outcome, and proof times refine the exposure path as above. Launch attestation time is assignment.issued_at <= launch.issued_at <= resolution.issued_at; it must be valid/fresh at validation and match expected nonce/resource/context. Launch nonce missing on both sides is an ERROR_INPUT pair, never proof of equality. Undefined/null values cannot satisfy any required equality.

## 7. Independent comparisons and evidence claims

The future baseline receives the same decoded records, operator profile, integrity and nested proof evidence, trust/time assumptions and data—not less information than CPC. Decision equality is acceptable. Rule-suite equivalence is not proof of population detection or human usability. Any practical burden claim needs recorded evidence and role limitations.

D1 must cover absence/null/type/empty/unknown and relation boundaries for every load-bearing field, plus compound incompleteness/contradiction. Semantic faults must be resealed correctly so integrity failure does not mask the intended predicate. D2 must examine actual capture/use and prospective persistence with changed/stale artifacts. D3 must preserve analysis denominators/exclusions and show residual LA usefulness. This contract specifies requirements; its new D1 evidence is pending at specification freeze. Historical contract 2.0.0 D1 runs, including failed runs and post-observation depth-setup corrections, remain evidence under their original version. The new 2.0.1 corpus and oracle are derived from existing development cases and must be resealed and frozen before their new run; this establishes a prospective replay boundary, not a novel confirmatory population or statistical generalization. Old 48-case legacy inputs and all 2.0.0 fixtures/results remain untouched. Retagging an old result cannot turn it into 2.0.1 conformance. D2 and D3 remain deferred.

## 8. Dispositions, diagnostics and accounting

- **ERROR_INPUT:** unreadable JSON, unsupported structure, required payload/proof/envelope field absent/null/wrong type/empty, malformed timestamp/digest encoding, unknown field/record type/unregistered extension. No admitted export.
- **REJECT:** independently established unauthorized/context/integrity/condition/registry/consent/purpose/temporal/linkage contradiction in interpretable evidence. No admitted export.
- **QUARANTINE:** missing entire required record or ambiguous outcome cardinality without stronger evidence. No admitted export.
- **ADMIT:** the complete supported input satisfies every required rule and contains no error/refusal.

Final chain precedence is **REJECT > ERROR_INPUT > QUARANTINE > ADMIT**. A totally unreadable root has only ERROR_INPUT. When a root/record is partly unsupported, implementations may evaluate only safely interpretable independent evidence: e.g. a readable signed assignment with wrong context still rejects even if an outcome or some other field is missing. They must not invent values, trust an invalid signature, or suppress stronger diagnostics because a downstream record is absent. If a malformed dependency prevents a relation from being evaluated, mark that relation NOT_EVALUABLE; do not fabricate a pass or contradiction. All detected diagnostics are retained with rule_id, affected record/proof path and disposition, without raw content.

ERROR_CONFIG blocks evaluation separately, never becomes ADMIT or a fabricated REJECT result. For a batch: received = admitted + rejected + quarantined + error_input + not_evaluated_config. Each input_ref appears once in exactly one admitted/exclusion/not-evaluated ledger. Duplicated case_id is diagnosed and cannot serve as a database uniqueness claim; operator input_ref remains unique. The adapter's future opaque-key merge must detect/report ambiguous external join cardinality and never assert that chain admission alone guarantees a globally unique outcome. Such a merge is a separately tested task, not silently added to the chain guarantee.

## 9. Design examples: expected decisions, not executed tests

1. Complete V2 chain, valid measured prompt/generation, observed pre-release commitment, identity/translation authorized and consent eligible: ADMIT.
2. Missing outcome_key or both payload launch_nonces: ERROR_INPUT unless an independent REJECT rule is also established.
3. Nonempty authoritative namespaces all map to plain while requested/resolved/assigned guided: REJECT.
4. Approved mapping Q_HINT→hint with all conditions hint and verified platform launch proof: ADMIT.
5. Missing outcome and validly evidenced conflicting namespace mapping: REJECT; outcome incompleteness retained diagnostically.
6. Missing outcome with otherwise valid available evidence: QUARANTINE.
7. Final commitment records expected registry digest but usage observer records changed consumed template bytes: REJECT.
8. All artifacts declared under the measured-required strong profile: REJECT; not an actual-use success.
9. Commitment written after release, or equal UTC commit/release: REJECT.
10. Core evidence malformed but an unrelated signed, safely interpretable assignment has wrong context: REJECT plus ERROR_INPUT diagnostic; no uncontrolled exception.

## 10. Completion and authority

The present authorized scope is a new depth specification, aligned implementation/profile/schema materialization and D1 re-verification. It excludes D2, D3 and manuscript revision. A specification freeze is not implementation correctness or D1 evidence; a finite synthetic D1 pass is not D2/D3 evidence, scientific DESIGN_PASS, MAIN_GO, license approval, public-release authority or submission readiness. Further experiments require authorization outside this scope. Preserve original receipts, failures and evidence classes; at most two substantive repair attempts per root defect before design/route reassessment. Neither tests, hashes nor AI review can supply scientific or human authority.
