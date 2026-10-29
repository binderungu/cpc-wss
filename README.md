# CPC/WSS: condition provenance and outcome preparation

**Source/evidence distribution, 29 October 2026.** Version tag: `repository-evidence-v2-20261029`. The software components and reader entry are unchanged; this version adds source-layout and evidence-access documentation.

CPC/WSS helps research developers, data stewards and analysts keep three decisions distinct: whether supplied condition assertions satisfy a contract, which saved source owns an outcome, and whether that outcome may enter a declared analytical table. CPC is the Condition Provenance Contract. WSS is the existing name of the accompanying reference workflow; no expansion of that label is assumed.

The integrated resource retains raw inputs and actual validation returns, exports admitted metadata and exclusions, derives outcomes from selected saved responses, evaluates native eligibility, performs singleton joins, and reports lineage and counts at their own event grains. A grain is the unit being counted, such as a received chain, help publication, follow-up or outcome row. These counts must not be added into one sample size.

The actual application reported with this software is the completed bounded CPC/WSS technical investigation, including its three scripted Moodle Feedback episodes. Moodle Feedback is the Moodle activity used to collect the sandbox responses. No second research application, external adoption, human learner study, or measured productivity or learning benefit is claimed.

## Version and source

- Repository: [binderungu/cpc-wss](https://github.com/binderungu/cpc-wss).
- Source/evidence distribution: [repository-evidence-v2-20261029](https://github.com/binderungu/cpc-wss/tree/repository-evidence-v2-20261029).
- Frozen executable-source base: [ccdc93e0d1272ee1e65915409cc95da35f35aa4b](https://github.com/binderungu/cpc-wss/tree/ccdc93e0d1272ee1e65915409cc95da35f35aa4b).
- Distribution tag: `repository-evidence-v2-20261029`. The earlier `repository-publication-v1-20261028` remains preserved.
- Component identities: WSS 1.12.0, CPC core 2.0.2, contract/schema 2.0.1 and equivalent-rules comparator 1.0.1. The optional native PHP helper retains its separate 1.10.0 identity.

The distribution tag identifies these frozen components plus documentation and archived evidence. It introduces no new code version. No DOI is assigned.

## Supported reuse

| Component | Inputs that can vary within the supported domain | Changes that need adaptation and new qualification |
|---|---|---|
| CPC admission/export | Raw chain bytes; compatible external profile, key registry and validation time | New proof semantics, unsupported schema features or a different trust model |
| Local retained-result adapter | Supported admission context, new store/run/input references | Another engine, durability model or transport |
| U01 controller and renderer | Compatible task/catalogue content, actors, context and native identifiers | A different condition vocabulary, workflow or generation catalogue |
| Native mapping | Supported Moodle Feedback instance, course, activity and item bindings | Another LMS or activity/event schema |
| Outcome derivation | Compatible exact-response lookup, rubric/version, task and selected-source bindings | Continuous values, another scale, or an arbitrary grader |
| Join and reporting | Complete compatible cohorts, external rows, native mappings and policy/snapshot identifiers | Another key schema, outcome domain, comparison-arm set or event-grain model |

CPC is profile-driven within its restricted contract. The current WSS U01 workflow is more specific: it uses hint/answer resources, five named generation configurations, Moodle Feedback semantics, integer outcomes from 0 to 4, and the fixed `CPC_REFERENCE`, `B0`, `B2` counterpart projection. This is bounded reuse, not a configuration-only route to arbitrary study designs.

The generation fields are `response_style`, `max_output_chars`, `include_rationale` and `seed`. Their supported tuples are:

| Configuration | Style | Character cap | Rationale | Seed |
|---|---|---:|---|---:|
| `G_BASE` | `expanded` | 1024 | `true` | 0 |
| `G_STYLE` | `compact` | 1024 | `true` | 0 |
| `G_CAP` | `expanded` | 640 | `true` | 0 |
| `G_RATIONALE` | `expanded` | 1024 | `false` | 0 |
| `G_SEED` | `expanded` | 1024 | `true` | 1 |

## Install from the pinned source tree

Use an extraction or checkout of the pinned version. The reader examples require CPython 3.12 and a local POSIX filesystem. The recorded qualification used CPython 3.12.13 on macOS/POSIX; it does not establish Linux, Windows or general cross-platform qualification. The examples need no third-party Python package, paid API, live Moodle connection, database or PHP.

Retain the actual layout:

| Repository path | Purpose |
|---|---|
| `software/src/wss_bridge/` | WSS interfaces and preparation workflow |
| `software/references/cpc_release/implementation/src/cpc2/` | Pinned CPC dependency |
| `software/references/comparator_release/` | Pinned comparator dependency |
| `spec/` | CPC normative contract |
| `examples/core/` | Four reused public synthetic fixtures and their context |
| `examples/retained_handoff/` | Saved three-episode records |
| `docs/API_AND_EXAMPLES.md` | Interface/output guide |
| `evidence/` | Selected preserved counterexamples and handoff findings |

Keep `software/src` beside `software/references`. Moving only `wss_bridge`, flattening the tree to `repo/src`, or treating it as an independently qualified pip package would break the intended relative dependency binding. The optional native PHP helper belongs to separately configured native acquisition and is unnecessary for the local examples.

## Minimal example: one existing public fixture

The public files `examples/core/admit.raw` and `examples/core/context.json` are an existing complete hint-condition fixture and its separate synthetic trust context. `examples/core/CASES.json[0]` binds them to historical input reference `CPC201-D1-004556`. From the repository root, a reader can inspect the API with:

```python
import json
import sys
from pathlib import Path

root = Path.cwd()
sys.path[:0] = [
    str(root / "software/src"),
    str(root / "software/references/cpc_release/implementation/src"),
]
from cpc2.api import validate_raw

ctx = json.loads((root / "examples/core/context.json").read_text())
raw = (root / "examples/core/admit.raw").read_bytes()
result = validate_raw(raw, ctx["profile"], ctx["key_registry"],
                      ctx["validation_time"],
                      input_ref="CPC201-D1-004556")
print(result["disposition"])
print(result["admitted_record"]["attributed_condition"])
print(result["admitted_record"]["artifact_version"])
```

The retained historical result for those exact bytes is:

```text
ADMIT
hint
baseline-v1
```

This is a quoted stored result, not a new execution performed for this revision. The input SHA-256 is `6178067bbf21b2b8fa59a9e00d0d3fcc080a8fbc5f7bb2e2abdc853b1b14e65d`; the context supplies validation time `2026-10-13T02:00:00Z`. The public case manifest records the expected `ADMIT`; the original matching result is in the locally retained D1 decisions, whose full public distribution remains pending. The example's synthetic trust strings are demonstration material, not deployment secrets.

`ADMIT` is a decision about supplied assertions. It neither verifies actual resource consumption nor supplies an outcome scalar. Use all received results with `partition_results` or `export_results` to preserve exclusions and accounting; do not construct a batch by selecting only its admissions.

## Broader existing offline example

The existing reader entry covers admission/export, retained adapter receipts, saved-source derivation, joining and the three-arm counterpart projection. From the extracted repository root:

```sh
python3.12 -m venv .venv
.venv/bin/python -I -B examples/offline_examples.py --output /tmp/cpc-wss-reader-run-01
```

Use a new output directory outside the package whose parent already exists. A virtual environment is optional. The reader entry inserts the pinned source paths and refuses network, subprocess and SQLite operations through its Python audit hook. It does not invoke a native connector or the full scientific runner. These commands are reader instructions; they were not executed during this document revision.

Expected artifacts include `core_results.json`, `core_export/`, `adapter_view.json`, `derived_outcomes/`, `new_derived_outcomes.json`, `join.json`, `counterparts.json` and `RESULT.json`. The four reused core fixtures have dispositions `ADMIT`, `REJECT`, `QUARANTINE` and `ERROR_INPUT`. The saved three-episode joins have terminals `JOINED`, `JOINED`, `NATIVE_MAPPING_HOLD`. Derived bookkeeping IDs can change; inspect source keys, lineage, values and states rather than expecting full byte equality. `RESULT.json` checks the example's engineering expectations, not scientific efficacy.

## Use with compatible data and interpret outputs

Supply the contract-compatible profile and registry separately from chain bytes. Keep actual received bytes, result envelopes, refused inputs and unresolved receipts. Rule identifiers and diagnostic paths help identify a disputed relation, but some paths use literal `.artifacts.entry.` or `.measured_components.entry.` segments; they are not universally concrete array-element pointers.

For U01 outcome preparation, supply an already saved compatible controller/analysis, exposure bytes and a frozen exact-response recipe. Each recipe score must be an integer from 0 to 4, excluding Boolean values. Unknown or invalid responses are not a default zero. Source ownership is the tuple `(operator source epoch, standard log record ID, item ID)` within the store; it is not learner identity, causal attribution or independent database truth.

Give `join.analyze` the complete declared cohort, all external rows, native mappings and a compatible `JoinPolicy`. Multiplicity is counted before native and value filtering. Only `JOINED` releases a scalar. A native hold or another terminal exclusion has a null joined value even when an external value exists. This in-memory join does not itself run the CPC core, acquire native records or write files. By contrast, export, adapter retention and outcome derivation write new local state when invoked.

`CPC_REFERENCE` uses CPC; `B0` is the native-centered full-information procedure; `B2` uses the separately written equivalent-rules implementation. Capture, catalogue, native mapping, join and reporting machinery are shared. The fixed projection requires all three arms. The separate restricted `B1` ablation abstained on all three episodes and is not a full-information comparison or a validated join result.

E3's two publications were designed into the completed example. Publication ordinal 1 owns its serialized outcome; ordinal 2 is a source-only `NOT_SUBMITTED` branch. The attempt is held despite admission/external multiplicities of 1/1. Its retained scalar 4 is withheld from the joined view. This does not measure the frequency of unexpected ambiguity in practice.

Four counterexamples, `D3-00014`, `D3-00029`, `D3-00044` and `D3-00059`, remain `ADMIT` / primary `JOINED` / physical `MISMATCH`: actual prompt and generation both differ from reported approved values. They are unmitigated. The scoped handoff result remains `UF5=NO_ADDED_LA_HANDOFF_VALUE`; `Y_next` remains `NOT_MEASURED` / `NOT_VALIDATED_HERE`. The scripted outcomes 4/4/4 are not learning gains.

## Evidence identity and availability

The versioned [data archive](data/README.md) now supplies the historical D1
corpus/reports/decisions, D2 trial history, D3 paired decisions/six-store metrics
and SQLite adapter, and source-bound historical join records. The original
selected fixtures, handoff and four counterexample reports remain in place.
The archive has a creator/version, file index, licence map and SHA256. It is a
synthetic research-evidence distribution, not an efficacy or adoption result.

Original freeze manifests remain exact;38 internal review/preservation files
are omitted and listed. Their references may stop an unmodified original
all-files replay guard. This subset is inspectable, not a newly qualified
turnkey sealed reproduction package. Failed comparator outputs are retained.
No new CPC/WSS run or signature verification accompanied this publication.

Historical D3 six-store results belong to d3-opaque-sqlite-join-1.0.0 [0,100],
not the current WSS integer 0–4 join. The 21 join-method records remain
source 1.11.0 engineering evidence with 9 byte-identical relevant modules in 1.12.0.
Zenodo is not used; no DOI or institutional/journal acceptance is claimed.

## Legacy runtime fields and history

Some fixed output schemas retain development-era fields such as `scientific_JLA_sufficiency`, `UF1_UF6`, `native_checkpoint`, `release`, `G0_count` and `G0_balance`, and the status `CANDIDATE_FOR_REVIEW_NOT_RELEASE_AUTHORIZED`. The current implementation validates or emits some of these exact values. They describe their frozen developmental context; they are not a live authorization service or a replacement for subsequent retained adjudication. For example, the child offline record's `NOT_RUN` native label does not erase separate parent native receipts. The later UF5 negative result remains explicit in the accompanying evidence.

The top-level README focuses on purpose, installation and supported data. `docs/history/` retains the earlier public README and manifest with their historical context. No runtime field was removed; old public commit/tag identities and negative results remain available.

## License and citation

Source/software remain MIT under `LICENSE.txt`. The new data archive uses the author-approved CC BY 4.0/MIT split defined in `data/LICENSE_MAP.csv` and `data/LICENSE_NOTICE.md`. Internal review conversations and third-party articles are not relicensed by this distribution. Cite software and data separately using their version and exact public tag/commit. An accepted article, final coauthor approval or DOI is not asserted.

## Source under repo/src

The complete frozen source tree is also directly browsable in
[`src/cpc_wss_u01_v1_12_0/`](src/cpc_wss_u01_v1_12_0/), including its `src/`,
`references/`, `native/` and source manifest. [`src/SOURCE_MIRROR_BINDING.json`](src/SOURCE_MIRROR_BINDING.json)
checks all 100 files against the existing `software/` copy. The existing reader
still imports from `software/`, preserving its tested relative context. This
is a packaging/source-location addition, not a new runtime qualification.
