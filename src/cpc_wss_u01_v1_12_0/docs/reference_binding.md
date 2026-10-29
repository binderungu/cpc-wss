# WP00 reference binding and operator declarations

This offline implementation pins CPC implementation **2.0.2**, contract **2.0.1**, schema **cpc-2.0.1**, and the independent rules comparator **1.0.1**. The 41 copied files are byte-identical to the historical source paths listed in `references/REFERENCE_MANIFEST.json`. The manifest's exact byte digest is `sha256:9c4dee342dc86a4c614a337f6891bdae63e8fd75b00f2267e3081de011bc62ad`. These are source-integrity statements, not runtime qualification, native verification, authority or scientific evidence.

The source trees remain in their required layouts:

- `references/cpc_release/implementation/src/cpc2/` and sibling `references/cpc_release/implementation/schemas/`. CPC resolves the schema directory relative to the package file; copying just the Python source would leave its dependency incomplete. The upstream package's `__main__.py` is retained as exact source, without execution or integration as a WSS command.
- `references/comparator_release/comparator/independent_rules.py` and sibling `references/comparator_release/implementation/spec/FIELD_REQUIREMENTS.json`. This comparator reads that JSON file **during import**. Configuration never imports it or adds either reference tree to the import path.

The pin excludes historical study runners, caches, fixture/profile/key-registry instances, run histories and real data. No profile, key material, approved content, sandbox settings or operator configuration instance is generated. Upstream files are preserved unchanged, including any source interfaces or limitations; this module does not repair or reinterpret the historical core or comparator.

## Configuration API

`configuration.py` depends only on the standard library and `wss_bridge.primitives`. Import has no filesystem, network, database, native, subprocess, pinned-package import or signing side effects. There is no CLI. `parse_operator_configuration(raw)` and `OperatorConfiguration.from_json(raw)` accept supplied JSON text/bytes. `OperatorConfiguration.from_mapping(value)` accepts an already-decoded closed mapping; callers needing duplicate-key detection must use the JSON entry point. Unknown fields, malformed values, unsupported versions and a different reference manifest digest raise `ContractError`.

| Required field | Structural meaning |
| --- | --- |
| `configuration_version` | Exactly `wss-operator-declaration-1.0`. |
| `configuration_ref` | Opaque configuration declaration identifier. |
| `scope_grant_ref` | `DeclarationRef` with required opaque `ref` and optional `sha256`; no grant evaluation. |
| `operator_ref` | Opaque operator declaration identifier. |
| `reference_manifest_digest` | Exact pinned manifest digest above; parser compares the value but does not inspect files. |
| `evidence_root_ref` | Opaque designated-root reference, not a filesystem path to open or create. |

`DeclarationRef(ref, sha256=None)` accepts identifiers and optional lowercase SHA-256 digests only. It does not resolve a reference, verify a signature, fetch content or accept embedded profile/registry/key objects. References are suppressed from normal dataclass representations; `to_dict()` deliberately exposes reference metadata for explicit serialization. Never place credentials, DSNs, signing keys or raw personal data in identifiers. Unknown fields such as `private_key` or an inline registry are rejected.

Optional `validation_time` is a supplied RFC3339 timestamp with an explicit timezone, or null. No current time is generated, and syntax does not establish freshness, expiry or a valid signing/validation interval. Optional `facts` has a closed set of names: `runtime_profile`, `key_registry`, `key_policy`, `role_policy`, `runtime_dependency`, `source_epoch`, `actor_registry`, `context_map`, `approved_content`, `outcome_recipe`, `sandbox_authorization`, `internal_material_rights` and `execution_grant`.

Each supplied fact is a `FactDeclaration`: `{state: PENDING, reference: null}` or `{state: DECLARED, reference: DeclarationRef}`. These descriptions express the JSON object shapes; they are not materialized operator inputs. A missing fact becomes `PENDING`; a null/invalid fact object raises an error. `PENDING` with a reference and `DECLARED` without a reference both fail closed. Unknown state labels such as `APPROVED`, `AUTHORIZED` or `VERIFIED` fail closed. Pending facts do not prevent generic offline construction and serialization, but cannot supply evidence for a dependent action. The normalized facts mapping is immutable.

`pending_facts` lists missing declarations and a missing validation time. An empty list does not mean readiness: every `DECLARED` reference remains an unverified claim. The configuration object has no ready/authorized property and never launches a dependent action. A scope/approval/profile/key/content claim supplied by a chain must never become its own trust root. The future coordinator must obtain operator context separately and evaluate its actual provenance, scope, validity and prerequisites outside this parser. The parser cannot certify how a caller obtained its input.

## Explicit source verification API

`verify_pinned_references(references_root)` is a separately invoked, read-only operation intended for a later authorized verification scope. It reads the manifest, requires its embedded expected byte digest and closed metadata, compares the exact file inventory, rejects symlinks and special files, and checks copied bytes/sizes against the pinned manifest. The manifest read is capped at 1 MiB; listed sources are regular-file checked, size checked and hashed incrementally with an exact-size bound, without buffering their full contents. These bounds do not qualify hostile-filesystem or concurrency behavior. Each manifest row records source path, destination path, size, historical source digest and copied digest. The verifier checks their binding but does not reopen historical originals. It never imports or evaluates copied source, schemas, comparator rules or operator objects.

The returned `ReferenceByteReceipt` has `evidence_class=SOURCE_BYTE_MATCH_ONLY`, the manifest digest and matched paths. Its dataclass constructor and serialization are not authenticators. A successful explicit check would describe files read during that call; it would not make later imports safe, prevent subsequent mutation or qualify a runtime. The verifier is not an atomic snapshot against concurrent hostile filesystem changes. Future execution must separately control the dependency tree and pin the actual interpreter/dependencies under the appropriate grant. Expected filesystem failures are sanitized as `ContractError`; no credentials or arbitrary file bytes are echoed.

## Current verification boundary

Only standard-library copying, file hashing and JSON metadata generation were used to preserve these reference bytes. The new WSS code and copied project code were not imported, executed, compiled, linted, parsed as an AST or tested. `verify_pinned_references`, configuration parsing and all object constructors remain unexecuted. No native checkpoint, experiment, service call, approval exercise, signing, profile freeze or manuscript change follows from this implementation. The four historical forged-registry counterexamples remain untouched, and byte preservation does not revise their substantive outcomes.
