# CPC/WSS integrated reference resource

MIT-licensed repository preparation v1, 28 October 2026. The remote repository
has not been created or published. This snapshot is prepared locally for public
release and retains the RC3-qualified executable source and examples.
Source remains WSS 1.12.0 / CPC core 2.0.2 / contract and schema 2.0.1.

CPC checks supplied condition/version assertions and produces typed admission
and export. WSS retains inputs/results and prepares selected-source outcomes,
native eligibility, singleton join/HOLD, lineage and grain-specific accounting.
Intended users are research software developers, data stewards and analysts.
Potential usefulness is reasoned; human benefit and external adoption were not measured.

## Install and use from a clean extraction

Requirements: CPython 3.12, POSIX local filesystem (fcntl/flock/fsync). No pip,
paid API, Moodle, Docker, database or network is needed for these examples.
Keep `software/src` and `software/references` together. Do not pip-install or
move only wss_bridge; its relative reference binding deliberately pins source.

From this directory:

```sh
python3.12 -m venv .venv
.venv/bin/python -I -B examples/offline_examples.py --output /tmp/cpc-wss-reader-run-01
```

The output path must not exist and its parent must exist. Each invocation uses a
new path. The script adds only this extracted package's two source directories
to the interpreter path. No network or subprocess is permitted in the example
process. A virtual environment is optional; `python3.12 -I -B` also works.
The portable installation method is an extracted source tree, not a PyPI wheel.
Only the actually recorded runtime is qualified; other platforms are untested.

The example exercises U1 admission, U2 export, U3 retained adapter receipts,
U4 derivation from a read-only saved controller, U5 join/HOLD and U6 the three-arm
denominator projection. See docs/API_AND_EXAMPLES.md for exact inputs and outputs.
It never calls run_offline, a native connector, helper, model or experiment runner.

## Interpret results

`RESULT.json` contains pass/fail expectations for engineering only. Four reused
D1 synthetic inputs yield ADMIT, REJECT, QUARANTINE, ERROR_INPUT respectively.
The retained three-episode source has three ADMIT and two JOINED / one native
HOLD with null value, across equally informed CPC/B0/B2 arms. E3 has admission
and external multiplicity 1/1; its HOLD is multi-publication native ambiguity.
Re-derived outcomes receive new bookkeeping IDs. Compare selected source keys,
lineage, values and states, not randomly generated IDs or full output bytes.

Four archived D2 remain ADMIT / primary JOINED / physical MISMATCH; actual prompt
AND generation differ from reported approved values. They are not mitigated.
Their exact reports and preservation receipt are included; HMAC is not replayed.
UF5 remains NO_ADDED_LA_HANDOFF_VALUE; STOP_CURRENT_JLA_FORMULATION. Values 4,4,4
are scripted fixtures, not learning gains. Y_next remains NOT_MEASURED /
NOT_VALIDATED_HERE. Shared comparison/capture/join/reporting is not CPC-exclusive.

## Files and evidence scope

* software/: exact frozen source, including historical README/docs and manifests.
  Read docs/CURRENT_BOUNDARIES.md before those historical stage descriptions.
* spec/: exact normative CPC 2.0.1 contract.
* examples/core/: four exact historical synthetic fixtures and a clearly marked
  SYNTHETIC_ONLY trust context. These public test strings must never be secrets.
* examples/retained_handoff/: exact previously reviewed reader-candidate evidence;
  includes historical local paths/UUIDs for provenance, not live configuration.
* evidence/: exact D2 receipts and UF5/T1–T4 negative findings.
* COPY_PROVENANCE.json and MANIFEST.sha256: byte identities, not scientific truth.

Private DB dumps, cookies, raw HTTP captures, current signing keys, real student
logs, private HIT contracts, manuscript and paid-provider credentials are excluded.
Reader-candidate naming in historical evidence does not itself grant publication.

## License and repository state

Copyright (c) 2026 Aditya Nur Cahyo. Licensed under the MIT License; see
[LICENSE.txt](LICENSE.txt) and [RIGHTS_AND_NOTICES.json](RIGHTS_AND_NOTICES.json).
The rights holder explicitly approved this grant on 28 October 2026. It covers
the project-authored source, internally vendored CPC/comparator, specification,
examples, synthetic evidence and documentation in this distribution. External
runtimes and SLPT source are not redistributed; their licenses are not changed.

The repository is prepared locally. There is no verified public URL, published
release, DOI, SoftwareX manuscript or submission associated with this snapshot.
Do not treat the proposed repository name as evidence of availability. Historical
NOT_AUTHORIZED/NOT_RUN labels inside frozen source and retained evidence describe
their original stage. The current license grant is recorded separately in
[NOTICE.md](NOTICE.md) and does not rewrite scientific or native history.

See [docs/REPOSITORY_STATE.md](docs/REPOSITORY_STATE.md) for the remaining publication
steps and [CITATION.md](CITATION.md) for an honest interim citation.
