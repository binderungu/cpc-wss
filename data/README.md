# CPC/WSS validation evidence, V3-20261029

This directory supplies the versioned synthetic data and historical source
supporting the CPC/WSS technical investigation. Creator: **Aditya Nur Cahyo**.

- [Download the evidence archive](CPC_WSS_VALIDATION_EVIDENCE_V3_20261029.zip). GitHub's **Raw/Download** action downloads the ZIP.
- [Per-file index](FILE_INDEX.csv), [licence map](LICENSE_MAP.csv),
  [licence notice](LICENSE_NOTICE.md), [archive contents and limits](ARCHIVE_README.md).
- [SHA256](CPC_WSS_VALIDATION_EVIDENCE_V3_20261029.zip.sha256): `ecd42a52e152476450df3019e13ecdb115ca8f3eb7fb8011445ef4b03f479724`.
- [Original freeze coverage](ORIGINAL_FREEZE_COVERAGE.json) and [omitted internal files](OMISSIONS.json).

The archive contains 9,804 exact original payloads: D1 frozen synthetic corpus
and results, D2 local mock traces, D3 paired decisions and six SQLite analytical
stores, failed comparator history, and historical source-bound join engineering
records. Data/collection documentation use CC BY 4.0; software bundles/code
retain MIT. The map defines each original file's scope; these licences are not
an either/or offer over the whole collection. No DOI is assigned.

Historical D3 results belong to `d3-opaque-sqlite-join-1.0.0` [0,100]. Current
WSS `join.analyze` uses integer 0–4. The 21-method receipt is historical source 1.11.0,
with 9 relevant modules identical to 1.12.0, not a new1.12.0 run.

Four D2 cases D3-00014/00029/00044/00059 remain ADMIT/primary JOINED/physical
MISMATCH; actual prompt AND generation differ from reported approved values.
UF5 remains NO_ADDED_LA_HANDOFF_VALUE and Y_next remains unmeasured. Counts and
views must not be pooled as independent samples. Scripted4/4/4 are not gains.

The 38 omitted files are internal review/preservation records. Original freeze
manifests are unchanged and may refer to those omitted files, so the old
all-files runner guards can stop on missing internal records. Do not weaken
guards or call this a turnkey sealed replay. Source, received inputs and stored
outputs can be inspected; their availability is distinct from independent
reproduction or scientific validity. Current private keys, backups, HTTP/cookies
and human learner data are not supplied. Test keys are intentionally synthetic.

Cite this dataset separately from the software, using the version-specific
GitHub tag `repository-evidence-v2-20261029` and [DATASET_METADATA.json](DATASET_METADATA.json). The final
commit SHA and anonymous download verification are recorded by the publication
controller after upload. GitHub access is not a claim of editorial approval of
the article or of every interpretation of a journal data policy.
