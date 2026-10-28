# Shared neutral counterpart projection — source 1.12.0

`counterparts` projects already stored CPC_REFERENCE, B0 and B2 outputs into the
same neutral representation. It neither invokes a validator/rules engine nor
accesses Moodle, a provider, a helper process or a native database. It does not
decide UF5 or fill inspector judgments.

The adopted method is
`CPC-WSS-WORKED-UF5-DENOMINATOR-V1-20261025`. Its three full-information
counterparts receive the same common bytes and policy/access receipt. All arms
reuse this trace/projection machinery. This sharing is explicit: a cosmetic arm
label or shared output machinery cannot become exclusive CPC utility.

## API and separation of boundaries

```python
from wss_bridge.counterparts import (
    read_verified_inputs, project_counterparts, write_counterparts,
    materialize_counterparts,
)

# Explicit bounded read of an existing closed runner inventory.
inputs = read_verified_inputs(existing_runner_root)
raw = inputs.pop("raw_inputs")

# Pure data projection; no file reads or output writes.
package = project_counterparts(**inputs)

# Explicit new-directory-only materialization, restricted local files.
receipt = write_counterparts(unused_output_root, package, raw_inputs=raw)

# The convenience boundary composes the same three operations.
package, receipt = materialize_counterparts(existing_runner_root, unused_output_root)
```

Pure inputs are the stored `handoff_report`, `terminal_controller_view` and
`episode_ledger`; optional `producer_consumptions` and `runner_start` add explicit
capture/plan provenance. Omitted metadata remains MISSING/UNKNOWN, rather than
being inferred from favorable core results or completed episodes. The exact
common inventory filename defaults to `RUNNER_MANIFEST.json`.

The read boundary verifies every declared runner payload against its supplied
manifest before projection. Each file is a bounded, regular, single-link leaf
under real directory ancestors. Absolute/traversal/noncanonical paths and
symlinks are refused. Aggregate input is at most 128 MiB, one file at most64 MiB,
and at most10,000 declared files. JSON duplicate keys and nonfinite constants
are rejected. These are cooperative local integrity checks, not WORM custody,
hostile-process isolation or independent authentication of the old manifest.

Producer ownership comes from the prospectively recorded producer index
metadata and one indexed consume-manifest. Actual prompt/generation/use
references are checked against the delivered captured bytes. No snapshot IDs
are backfilled from payload shapes, and capture bytes do not become proof of a
truthful or independent observer. The four historical D2 remain unmitigated.

## Preserved decisions and partial states

The module requires identical full-information input scopes and common/access
receipts across all three arms. Each neutral row copies the original arm's
result/disposition, native mapping, terminal reason and value. It does not copy
the CPC decision into B0/B2, recompute a core result, impute a missing score to0,
pick a preferred valid outcome, deduplicate a singleton or alter historical
failure states. Contradictory stored row/count partitions are refused.

One row per received core receipt is distinct from source-only/no-complete-chain
branches. E3 preserves all publications, one owner and nonowner
NO_OUTCOME_CHAIN/NOT_SUBMITTED without a fabricated fourth core input. A failed
invocation or held/pending operation is visible as its actual branch kind, not
a fabricated REJECT/QUARANTINE. Original full arm outputs and all common source
documents remain in the delivery for unprojected detail.

The renderer's finite outcome values are copied from retained outcome records;
this module never executes the outcome recipe. Ambiguous multiple outcome
matches remain unavailable rather than selecting the first. Original decision
and derived source value can disagree; projection preserves that disagreement
for inspection instead of silently repairing it.

## Output

New output contains:

- `common/`: byte-exact manifest and all declared runner input/output bytes,
  copied once and shared by all arms.
- For each arm: `scope.json`, `core_rows.jsonl`, `source_only_rows.jsonl`,
  `denominator.jsonl`, `field_crosswalk.json`, `original_arm_output.json`.
- `COUNTERPARTS.json`, `BOUNDARIES.json` and an output `MANIFEST.json`.

Fields carry concrete delivered relative-path/JSON-pointer locators or explicit
MISSING/UNRESOLVED states. Crosswalk metadata is not recursively mapped to
itself. Prefix-native counts and separately supplied terminal-controller counts
remain distinct. The current analysis reference is named separately; snapshots
alone do not prove a complete event delta. The terminal object digest is a
canonical-JSON digest; original file bytes/digest remain in the common inventory.

Before writing, the writer checks that the supplied common file set exactly
matches its runner manifest, hashes every payload and reconstructs the pure
projection to detect mixed or changed source/view objects. Output paths are
exclusive. Existing leaves/retry are refused, and any partial failed write is
retained. No network publication, access grant or public-release authorization
is supplied.

## Deliberate evidence limits

`actual_protocol_helper_calls` remains UNKNOWN in the neutral denominator:
controller ingestions/wire envelopes do not prove actual helper launches. A
future outer execution manifest must separately bind actual acquisition/process,
submit-attempt, timing, authority and rights receipts. Inspectors must use that
common outer inventory for those grains. This module cannot certify them from
offline runner output.

Inherited `reporting._BOUNDARIES` labels—including
SYNTHETIC_OFFLINE_MECHANICAL_QA and native_checkpoint NOT_RUN—are preserved
exactly in `inherited_boundaries` and the common raw report. A parent workflow
must distinguish any separately observed native acquisition from the offline
computation/projection labels. No wrapper may promote an engine mode into
native truth.

`UF5=NOT_ADJUDICATED`, empty inspection records, unchanged Y_next/claim boundaries
and the four D2 are retained. Equal neutral capabilities are allowed. T1–T4 and
the residual-feature decision remain a separate scientific inspection; equality
does not automatically prove usefulness, novelty, no-added-value or JLA fit.

The local QA uses stored artificial engineering evidence and synthetic mutations
only. It is not a new worked demonstration, native experiment, scientific
replication or human-effort study.
