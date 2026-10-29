# SC01 repair contract — offline source 1.10.0

Scope is a new source version and offline mechanical qualification only. Parent 1.9.0, frozen WP results, D1–D3, prior configuration and manuscripts stay unchanged. No native calls, Moodle/LIRA, Docker/VM, paid APIs, source-data queries, or checkpoint. G0 root/count/balance remain unresolved without reset. Four archived D2 remain unmitigated ADMIT / primary JOINED / physical MISMATCH; both actual prompt and generation differ from reported. Y_next remains NOT_MEASURED / NOT_VALIDATED_HERE.

## Normative semantics

1. `NativeTarget.courseid` continues to mean the positive Moodle **context course**. It binds cm.course, feedback.course, event course and module context. Zero is never legal for those native IDs.
2. New explicit `NativeTarget.feedback_route` must be `ordinary_course`. Site/front-page Feedback is unsupported in this version, not a fallback route.
3. New explicit `NativeTarget.response_scope_courseid` is the exact integer **0** for this route. It binds both feedback_completed.courseid and feedback_value.course_id. Missing remains null/unresolved; true/false, string "0", float0.0, negative and arbitrary nonzero are never coerced to zero. No default inference from context IDs or response rows.
4. `NativeValueSnapshot.completed_courseid` and `value_courseid` retain the source-native values and names. Zero is valid for these two scope fields only; other native identity-zero guards remain intact. Context/actor/Feedback/item/value/completed/time/digest guards remain intact.
5. Ordinary-course status must be checked from source metadata, not merely declared: join `course.id = cm.course`, require observed course.category >0. Moodle 5.2.4 get_site() identifies site course via category0. Add `course` to the fixed InnoDB/SELECT projection, for **nine tables**, and retain raw before/after course-category metadata. This is a declared change to schema/principal policy, not a hidden privilege extension. Null/zero category is unresolved/unsupported; no answer query after invalid before-target.
6. New receipt field `target_course_category` carries the actual nonnegative category observed in the before-target metadata; null stays null. Binding validation requires positive category for the supported route. This field is a reported source fact, not source authenticity. Invalid/changed after-target still holds; the before fact is not rewritten.
7. PHP input parser, Python closed dataclasses/serializers, controller readiness, metadata/capture consumers and fixtures must share these semantics. New protocol `wss-native-read-1.1` rejects old wire1.0. Controller journal format becomes `wss-controller-v2`; no silent history migration or re-labeling. Legacy partial mappings may be represented with null new fields but cannot qualify an anchor.
8. Same-ID duplicate comparison includes reported category facts; changed known category is SOURCE_CONFLICT, missing category cannot be rescued as a qualified duplicate. Occurrence identity remains (source epoch, positive native log ID); completed IDs/content hashes do not replace it.

## Required acceptance evidence (declared before edits)

- Reproduce old helper/contract conflict with source-faithful scope0 synthetic data, preserving the failing baseline as expected diagnosis.
- Positive fake-provider PHP read: positive context course, ordinary category, response scopes0, unchanged exact source bytes; Python transport, binding/capture and controller accept the coherent offline record.
- Negative cases: missing/wrong type/unsupported route/scope declarations; scope positive/nonzero/missing/bool; site category0, missing category; context course0/wrong cm/Feedback/context/log/actor/item/completed/value; no answer query on failed completed binding. Existing unknown result, anonymity, impersonation, overflow, ambiguity, TLS/backend/engine and raw-byte checks must remain covered.
- Reject wire1.0 and old context/history; preserve partial raw facts and ambiguity. Do not erase zeros, replace expected with observed, or weaken native route checks.
- Read official pinned XMLDB/PHP as text only; prove source semantics and all nine table projection fields. No executing Moodle source.
- Lint PHP, compile/import new Python source inertly, run scoped PHP/Python seam and controller tests, then relevant frozen-suite regression copied into the new packet with **declared fixture adaptations**. Fresh PHP wire fixtures must come from the new helper; do not modify archived wire receipts or normalize legacy blobs in place.
- Retain failures/diagnoses if encountered; independently review the final contract/diff/evidence without editing, address findings in new source and rerun affected gates only.
- Check hashes of parent/source/config/archived evidence and four D2 receipts after verification. Distinguish local SC01 repair PASS from native/checkpoint/JLA readiness (all still unestablished).

### Review corrections included before final freeze
Completed ID and required modification time are checked before the value query; wrong/missing IDs and time retain metadata without answer reads. Source-window category/course/cmid coherence is checked on every status including NO_MATCH, independently of occurrence/snapshot cardinality. Old controller journals are rejected by executable read-only tests without migration.
