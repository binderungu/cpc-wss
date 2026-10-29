"""Safe, partial semantic evaluation of contract 2.0.1 evidence.

This module never exports, captures bytes, builds fixtures or supplies trust
roots. Schema diagnostics remain the runner's responsibility. Missing or
untrusted dependencies produce NOT_EVALUABLE; they cannot prove equality.
"""
from __future__ import annotations

from .common import DIGEST_RE, diagnostic, is_identifier, parse_time, proof_object_digest
from .integrity import verify_proof, verify_record

CLASSES = ('assignment', 'resolution', 'exposure', 'outcome')
CONTEXT = ('contract_version', 'profile_id', 'profile_version', 'experiment_id',
           'experiment_version', 'unit_token', 'audience', 'deployment_id', 'context_id')


def validate_chain(chain, profile, key_registry, validation_time):
    """Return sanitized rule diagnostics, including unavailable dependencies.

    Caller must first validate the separately supplied frozen profile and key
    registry and collect closed-field schema errors. Trusted signatures support
    relation evaluation, never the truth of consumption or consent assertions.
    """
    out = []
    now = parse_time(validation_time)
    if now is None:
        return [diagnostic('R01', 'trusted_validation_time_unavailable', '$', 'NOT_EVALUABLE')]
    def add(rule, code, path, disposition='REJECT'):
        out.append(diagnostic(rule, code, path, disposition))
    def unavailable(rule, code, path):
        add(rule, code, path, 'NOT_EVALUABLE')
    def ident(v):
        return is_identifier(v, profile['input_limits']['max_identifier_chars'])
    def hash_value(v):
        return isinstance(v, str) and bool(DIGEST_RE.fullmatch(v))
    def integer(v):
        return type(v) is int and v >= 0
    def equal(left, right, path, rule, code, typed=ident, trusted=True):
        if not trusted or not typed(left) or not typed(right):
            unavailable(rule, code + '_dependency_unavailable', path)
        elif left != right:
            add(rule, code, path)
    def domain(value, allowed, path, rule, code, trusted=True):
        if not trusted or not ident(value):
            unavailable(rule, code + '_dependency_unavailable', path)
        elif value not in allowed:
            add(rule, code, path)
    def order(left, right, path, rule, code, strict=False, trusted=True):
        a, b = parse_time(left), parse_time(right)
        if not trusted or a is None or b is None:
            unavailable(rule, code + '_dependency_unavailable', path)
        elif not (a < b if strict else a <= b):
            add(rule, code, path)
    def freshness(obj, path):
        a, b, c = (parse_time(obj.get(k)) for k in ('valid_from', 'issued_at', 'expires_at'))
        if any(t is None for t in (a, b, c)):
            unavailable('R01', 'freshness_dependency_unavailable', path)
        elif not (a <= b < c and b <= now and a <= now < c):
            add('R01', 'freshness_conflict', path)
    def context(obj, path, record=None, trusted=True, schema=False):
        expected = {k: profile[k] for k in ('contract_version', 'profile_id', 'profile_version',
                    'experiment_id', 'experiment_version')}
        expected.update(audience=profile['expected_audience'], deployment_id=profile['deployment_id'],
                        context_id=profile['context_id'])
        if schema:
            expected['schema_version'] = profile['schema_version']
        # External policy comparisons are independently decidable even if the
        # signature is invalid. The invalid signature remains a refusal.
        for field, value in expected.items():
            equal(obj.get(field), value, path + '.' + field, 'R01', 'external_context_conflict')
        for field in ('contract_version', 'profile_id', 'profile_version'):
            equal(obj.get(field), chain.get(field), path + '.' + field, 'R01', 'routing_context_conflict')
        if record is not None:
            for field in CONTEXT:
                equal(obj.get(field), record.get(field), path + '.' + field, 'R01',
                      'bound_context_conflict', trusted=trusted)
        freshness(obj, path)

    # Privacy rejection inspects parsed keys independently, but neither keys nor
    # values are interpolated into diagnostics. List indices are safe paths.
    def private_leaf(key):
        leaf = key.replace(':', '.').rsplit('.', 1)[-1]
        return ''.join(c for c in leaf.casefold() if c.isalnum())
    deny = {private_leaf(k) for k in profile['privacy_denylist']}
    def privacy(value, path='$'):
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str) and private_leaf(key) in deny:
                    add('R01', 'policy_forbidden_parsed_field', path)
                privacy(child, path + '.object')
        elif isinstance(value, list):
            for i, child in enumerate(value):
                privacy(child, path + '[' + str(i) + ']')
    def extensions(obj, path):
        ext = obj.get('extensions')
        if isinstance(ext, dict):
            for key in ext:
                if key not in profile['extension_keys']:
                    add('I03', 'unregistered_extension', path + '.extensions', 'ERROR_INPUT')
    if not isinstance(chain, dict):
        return out
    privacy(chain)
    for field in ('contract_version', 'profile_id', 'profile_version'):
        equal(chain.get(field), profile[field], '$.' + field, 'R01', 'external_routing_conflict')
    records = chain.get('records')
    if not isinstance(records, list):
        return out
    groups = {kind: [] for kind in CLASSES}
    verified = {}
    record_ids, nonces, proof_ids = set(), set(), set()
    proofs = {}
    trusted_objects = []
    def proof_at(value, kind, path, parent, parent_ok):
        if not isinstance(value, dict) or not isinstance(value.get('body'), dict):
            unavailable('R01', 'proof_dependency_unavailable', path)
            return ({}, False)
        body = value['body']
        ok, diagnostics = verify_proof(value, kind, profile, key_registry, path)
        out.extend(diagnostics)
        if ok:
            trusted_objects.append((body, path + '.body'))
        context(body, path + '.body', parent, ok and parent_ok)
        extensions(body, path + '.body')
        pid = body.get('proof_id')
        if ident(pid):
            if pid in proof_ids:
                add('R08', 'duplicate_proof_id', path + '.body.proof_id')
            proof_ids.add(pid)
        return body, ok
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        path = '$.records[' + str(index) + ']'
        for field, seen in (('record_id', record_ids), ('nonce', nonces)):
            value = record.get(field)
            if ident(value):
                if value in seen:
                    add('R08', 'duplicate_' + field, path + '.' + field)
                seen.add(value)
        if record.get('record_type') not in CLASSES:
            continue
        kind = record['record_type']
        groups[kind].append((record, path))
        ok, diagnostics = verify_record(record, profile, key_registry, path)
        out.extend(diagnostics)
        verified[id(record)] = ok
        if ok:
            trusted_objects.append((record, path))
        context(record, path, schema=True)
        extensions(record, path)
        payload = record.get('payload')
        if not isinstance(payload, dict):
            continue
        if kind == 'assignment':
            for field in ('predecessor_record_id', 'predecessor_digest'):
                if field not in record:
                    unavailable('R07', 'assignment_predecessor_dependency_unavailable', path + '.' + field)
                elif record[field] is not None:
                    typed = ident if field == 'predecessor_record_id' else hash_value
                    if typed(record[field]):
                        add('R07', 'assignment_predecessor_conflict', path + '.' + field)
                    else:
                        unavailable('R07', 'assignment_predecessor_dependency_unavailable', path + '.' + field)
        if kind == 'resolution':
            launch = payload.get('launch_attestation')
            proofs[(id(record), 'launch_attestation')] = (*proof_at(launch, 'launch_attestation',
                        path + '.payload.launch_attestation', record, ok), launch)
        if kind == 'exposure':
            commit = payload.get('commitment')
            cb, cok = proof_at(commit, 'commitment', path + '.payload.commitment', record, ok)
            proofs[(id(record), 'commitment')] = (cb, cok, commit)
            usage = cb.get('usage_attestation')
            proofs[(id(record), 'usage_attestation')] = (*proof_at(usage, 'usage_attestation',
                        path + '.payload.commitment.body.usage_attestation', record, ok), usage)
            release = payload.get('release_attestation')
            proofs[(id(record), 'release_attestation')] = (*proof_at(release, 'release_attestation',
                        path + '.payload.release_attestation', record, ok), release)
    # Cross-object unit consistency is independent of missing intermediates or
    # cardinality ambiguity. No object is selected to supply attribution.
    for i, (left, _) in enumerate(trusted_objects):
        for right, path in trusted_objects[i + 1:]:
            equal(left.get('unit_token'), right.get('unit_token'), path + '.unit_token',
                  'R07', 'shared_unit_conflict')
    condition_claims = []
    for kind, items in groups.items():
        fields = {'assignment': ('assigned_condition',), 'resolution': ('requested_condition', 'resolved_condition'),
                  'exposure': ('enacted_condition',), 'outcome': ('attributed_condition',)}[kind]
        for record, path in items:
            p = record.get('payload')
            if verified.get(id(record), False) and isinstance(p, dict):
                for field in fields:
                    condition_claims.append((p.get(field), path + '.payload.' + field))
    for i, (left, _) in enumerate(condition_claims):
        for right, path in condition_claims[i + 1:]:
            equal(left, right, path, 'R02', 'shared_condition_conflict')
    for kind, items in groups.items():
        if not items:
            add('Q01', 'missing_record_class', '$.records.' + kind, 'QUARANTINE')
        elif len(items) > 1:
            add('Q02' if kind == 'outcome' else 'R08', 'ambiguous_record_class', '$.records.' + kind,
                'QUARANTINE' if kind == 'outcome' else 'REJECT')
    def one(kind):
        return groups[kind][0] if len(groups[kind]) == 1 else ({}, '$.records.' + kind)
    assignment, ap = one('assignment')
    resolution, rp = one('resolution')
    exposure, ep = one('exposure')
    outcome, op = one('outcome')
    def payload(record):
        value = record.get('payload')
        return value if isinstance(value, dict) else {}
    def signed(record):
        return verified.get(id(record), False)
    def dg(record):
        integrity = record.get('integrity')
        return integrity.get('content_digest') if isinstance(integrity, dict) else None
    def pinfo(record, kind):
        return proofs.get((id(record), kind), ({}, False, None))
    def registry_vector(obj, path):
        bundle, artifacts = obj.get('artifact_version'), obj.get('artifacts')
        domain(bundle, profile['artifact_registry'], path + '.artifact_version', 'R05', 'artifact_bundle_domain')
        expected = profile['artifact_registry'].get(bundle) if ident(bundle) else None
        if not isinstance(expected, dict) or not isinstance(artifacts, dict):
            unavailable('R05', 'registry_vector_dependency_unavailable', path + '.artifacts')
            return None
        if set(expected) - set(artifacts):
            add('I02', 'artifact_components_missing', path + '.artifacts', 'ERROR_INPUT')
        if set(artifacts) - set(expected):
            add('I03', 'artifact_components_unknown', path + '.artifacts', 'ERROR_INPUT')
        for component in expected.keys() & artifacts.keys():
            entry = artifacts[component]
            if isinstance(entry, dict):
                for field in ('version', 'digest', 'evidence_mode'):
                    equal(entry.get(field), expected[component][field], path + '.artifacts.entry.' + field,
                          'R05', 'registry_entry_conflict', typed=hash_value if field == 'digest' else ident)
        for component in profile['required_measured_components']:
            entry = artifacts.get(component)
            if isinstance(entry, dict) and ident(entry.get('evidence_mode')) and entry['evidence_mode'] != 'measured':
                add('R05', 'measured_component_declared', path + '.artifacts.entry.evidence_mode')
        return expected
    # Every available child is checked; there is never a first-record selection
    # in an ambiguous class. Ancestor availability is a relation dependency.
    ancestor = {'resolution': assignment, 'exposure': resolution, 'outcome': exposure}
    for kind, items in groups.items():
        for record, path in items:
            if kind in ancestor:
                prev = ancestor[kind]
                trusted = signed(record) and signed(prev)
                equal(record.get('predecessor_record_id'), prev.get('record_id'), path + '.predecessor_record_id',
                      'R07', 'predecessor_id_conflict', trusted=trusted)
                equal(record.get('predecessor_digest'), dg(prev), path + '.predecessor_digest', 'R07',
                      'predecessor_digest_conflict', typed=hash_value, trusted=trusted)
                for field in CONTEXT:
                    equal(record.get(field), prev.get(field), path + '.' + field, 'R07',
                          'ancestor_context_conflict', trusted=trusted)
                order(prev.get('issued_at'), record.get('issued_at'), path + '.issued_at', 'R07',
                      'record_issuance_order', trusted=trusted)

    # Per-record policy predicates continue across missing or ambiguous classes.
    for record, path in groups['assignment']:
        p = payload(record)
        domain(p.get('assigned_condition'), profile['conditions'], path + '.payload.assigned_condition', 'R02', 'condition_domain')
        equal(p.get('assignment_policy_version'), profile['assignment_policy_version'], path + '.payload.assignment_policy_version', 'R02', 'assignment_policy_conflict')
        equal(p.get('scope'), profile['scope'], path + '.payload.scope', 'R02', 'scope_conflict')
        resource = p.get('resource_id')
        domain(resource, profile['resource_condition_map'], path + '.payload.resource_id', 'R02', 'resource_domain')
        if ident(resource) and resource in profile['resource_condition_map']:
            equal(p.get('assigned_condition'), profile['resource_condition_map'][resource], path + '.payload.assigned_condition', 'R02', 'resource_condition_conflict')
    for record, path in groups['resolution']:
        p = payload(record)
        for field in ('requested_condition', 'resolved_condition'):
            domain(p.get(field), profile['conditions'], path + '.payload.' + field, 'R02', 'condition_domain')
        equal(p.get('resolver_version'), profile['resolver_version'], path + '.payload.resolver_version', 'R02', 'resolver_version_conflict')
        for field in ('requested_condition', 'resolved_condition'):
            equal(p.get(field), payload(assignment).get('assigned_condition'), path + '.payload.' + field,
                  'R02', 'same_condition_conflict', trusted=signed(record) and signed(assignment))
        lb, lok, _ = pinfo(record, 'launch_attestation')
        lp = path + '.payload.launch_attestation.body'
        trust = signed(record) and lok
        domain(lb.get('resource_id'), profile['resource_condition_map'], lp + '.resource_id', 'R02', 'launch_resource_domain')
        if ident(lb.get('resource_id')) and lb['resource_id'] in profile['resource_condition_map']:
            derived = profile['resource_condition_map'][lb['resource_id']]
            for field in ('requested_condition', 'resolved_condition'):
                equal(derived, p.get(field), path + '.payload.' + field, 'R02', 'launch_resource_condition_conflict', trusted=trust)
        for field, expected in (('assignment_record_id', assignment.get('record_id')),
                                ('resource_id', payload(assignment).get('resource_id')),
                                ('launch_nonce', payload(assignment).get('launch_nonce'))):
            equal(lb.get(field), expected, lp + '.' + field, 'R04', 'launch_assignment_binding', trusted=trust and signed(assignment))
        equal(lb.get('assignment_digest'), dg(assignment), lp + '.assignment_digest', 'R04', 'launch_assignment_digest',
              typed=hash_value, trusted=trust and signed(assignment))
        equal(p.get('launch_nonce'), lb.get('launch_nonce'), path + '.payload.launch_nonce', 'R04', 'launch_resolution_nonce', trusted=trust)
        order(assignment.get('issued_at'), lb.get('issued_at'), lp + '.issued_at', 'R04', 'assignment_launch_order', trusted=trust and signed(assignment))
        order(lb.get('issued_at'), record.get('issued_at'), lp + '.issued_at', 'R04', 'launch_resolution_order', trusted=trust)
        namespaces = p.get('claim_namespaces')
        attested = lb.get('namespace_values')
        raw_valid = lambda v: isinstance(v, dict) and bool(v) and all(ident(k) and ident(x) for k, x in v.items())
        equal(namespaces, attested, path + '.payload.claim_namespaces', 'R03', 'attested_namespaces_conflict', typed=raw_valid, trusted=trust)
        for raw_map, map_path, authenticated in ((namespaces, path + '.payload.claim_namespaces', trust),
                                                (attested, lp + '.namespace_values', lok)):
            if not isinstance(raw_map, dict):
                unavailable('R03', 'namespace_mapping_dependency_unavailable', map_path)
                continue
            for name in raw_map:
                if name not in profile['namespace_policy']:
                    add('R03', 'unknown_namespace', map_path)
            mapped_conditions = []
            for name, policy in profile['namespace_policy'].items():
                if policy['required'] and name not in raw_map:
                    add('I02', 'required_namespace_missing', map_path, 'ERROR_INPUT')
                if policy['role'] in ('authoritative', 'consistency') and name in raw_map:
                    raw, mapping = raw_map[name], policy['mapping']
                    if not ident(raw):
                        unavailable('R03', 'namespace_value_dependency_unavailable', map_path)
                    elif raw not in mapping:
                        add('R03', 'unmapped_namespace_value', map_path)
                    else:
                        mapped_conditions.append(mapping[raw])
                        for field in ('requested_condition', 'resolved_condition'):
                            equal(mapping[raw], p.get(field), map_path, 'R03', 'mapped_condition_conflict', trusted=authenticated and signed(record))
                        equal(mapping[raw], payload(assignment).get('assigned_condition'), map_path,
                              'R03', 'mapped_assignment_conflict', trusted=authenticated and signed(assignment))
            for i, left in enumerate(mapped_conditions):
                for right in mapped_conditions[i + 1:]:
                    equal(left, right, map_path, 'R03', 'mapped_namespaces_disagree', trusted=authenticated)
        used, authorized, ref = (p.get(k) for k in ('fallback_used', 'fallback_authorized', 'authorization_ref'))
        if type(used) is bool and type(authorized) is bool:
            if not used and (authorized or ident(ref)):
                add('R06', 'unused_fallback_authorization_conflict', path + '.payload.authorization_ref')
            elif not used and ('authorization_ref' not in p or ref is not None):
                unavailable('R06', 'fallback_reference_dependency_unavailable', path + '.payload.authorization_ref')
            elif used:
                if not authorized:
                    add('R06', 'fallback_not_authorized', path + '.payload.fallback_authorized')
                domain(ref, profile['fallback_permissions'], path + '.payload.authorization_ref', 'R06', 'fallback_permission_domain')
                if ident(ref) and ref in profile['fallback_permissions']:
                    permission = profile['fallback_permissions'][ref]
                    for field in ('requested_condition', 'resolved_condition'):
                        equal(p.get(field), permission['condition'], path + '.payload.' + field, 'R06', 'fallback_condition_conflict')
                    domain(payload(exposure).get('artifact_version'), permission['artifact_versions'],
                           ep + '.payload.artifact_version', 'R06', 'fallback_bundle_conflict', trusted=signed(record) and signed(exposure))
        else:
            unavailable('R06', 'fallback_dependency_unavailable', path + '.payload')

    for record, path in groups['exposure']:
        p = payload(record)
        domain(p.get('enacted_condition'), profile['conditions'], path + '.payload.enacted_condition', 'R02', 'condition_domain')
        equal(p.get('enacted_condition'), payload(resolution).get('resolved_condition'), path + '.payload.enacted_condition',
              'R02', 'enacted_condition_conflict', trusted=signed(record) and signed(resolution))
        registry_vector(p, path + '.payload')
        artifacts = p.get('artifacts')
        vector_typed = lambda v: isinstance(v, dict) and all(isinstance(e, dict) and ident(e.get('version')) and
                              hash_value(e.get('digest')) and ident(e.get('evidence_mode')) for e in v.values())
        cb, cok, commit = pinfo(record, 'commitment')
        ub, uok, _ = pinfo(record, 'usage_attestation')
        rb, rok, _ = pinfo(record, 'release_attestation')
        cp, up, xp = path + '.payload.commitment.body', path + '.payload.commitment.body.usage_attestation.body', path + '.payload.release_attestation.body'
        registry_vector(cb, cp)
        domain(cb.get('enacted_condition'), profile['conditions'], cp + '.enacted_condition', 'R02', 'commitment_condition_domain')
        equal(cb.get('enacted_condition'), payload(resolution).get('resolved_condition'), cp + '.enacted_condition',
              'R02', 'commitment_resolution_condition_conflict', trusted=cok and signed(resolution))
        for body, ok, bp in ((cb, cok, cp), (ub, uok, up), (rb, rok, xp)):
            equal(body.get('invocation_id'), p.get('invocation_id'), bp + '.invocation_id', 'R05', 'invocation_binding_conflict', trusted=ok and signed(record))
            equal(body.get('clock_id'), profile['observer_clock_id'], bp + '.clock_id', 'R07', 'observer_clock_conflict')
        for left, left_ok, right, right_ok, bp in ((ub, uok, cb, cok, cp), (cb, cok, rb, rok, xp)):
            equal(left.get('invocation_id'), right.get('invocation_id'), bp + '.invocation_id',
                  'R05', 'proof_invocation_conflict', trusted=left_ok and right_ok)
            for field in ('resolution_record_id', 'resolution_digest'):
                if right is cb:
                    equal(left.get(field), right.get(field), bp + '.' + field, 'R07', 'proof_resolution_binding',
                          typed=hash_value if field.endswith('digest') else ident, trusted=left_ok and right_ok)
        for body, ok, bp in ((cb, cok, cp), (ub, uok, up)):
            equal(body.get('resolution_record_id'), resolution.get('record_id'), bp + '.resolution_record_id', 'R07', 'resolution_id_binding', trusted=ok and signed(resolution))
            equal(body.get('resolution_digest'), dg(resolution), bp + '.resolution_digest', 'R07', 'resolution_digest_binding', typed=hash_value, trusted=ok and signed(resolution))
        for field in ('enacted_condition', 'artifact_version'):
            equal(cb.get(field), p.get(field), cp + '.' + field, 'R05', 'commitment_exposure_binding', trusted=cok and signed(record))
        equal(cb.get('artifacts'), artifacts, cp + '.artifacts', 'R05', 'commitment_vector_conflict', typed=vector_typed, trusted=cok and signed(record))
        committed_vector = cb.get('artifacts')
        if isinstance(committed_vector, dict) and isinstance(artifacts, dict):
            for component in committed_vector.keys() & artifacts.keys():
                a, b = committed_vector[component], artifacts[component]
                if isinstance(a, dict) and isinstance(b, dict):
                    for field in ('version', 'digest', 'evidence_mode'):
                        equal(a.get(field), b.get(field), cp + '.artifacts.entry.' + field,
                              'R05', 'commitment_component_conflict', typed=hash_value if field == 'digest' else ident,
                              trusted=cok and signed(record))
        equal(rb.get('exposure_record_id'), record.get('record_id'), xp + '.exposure_record_id', 'R07', 'release_exposure_binding', trusted=rok and signed(record))
        equal(rb.get('release_boundary'), profile['release_boundary'], xp + '.release_boundary', 'R07', 'release_boundary_conflict')
        if cok and rok and isinstance(commit, dict):
            try:
                cdigest = proof_object_digest(commit)
            except (ValueError, TypeError, UnicodeEncodeError, RecursionError):
                unavailable('R07', 'commitment_digest_dependency_unavailable', xp + '.commitment_digest')
            else:
                equal(rb.get('commitment_digest'), cdigest, xp + '.commitment_digest', 'R07', 'complete_commitment_digest_conflict', typed=hash_value)
        else:
            unavailable('R07', 'commitment_digest_dependency_unavailable', xp + '.commitment_digest')
        measured = ub.get('measured_components')
        if isinstance(measured, dict):
            if set(profile['required_measured_components']) - set(measured):
                add('I02', 'measured_components_missing', up + '.measured_components', 'ERROR_INPUT')
            if set(measured) - set(profile['required_measured_components']):
                add('I03', 'measured_components_unknown', up + '.measured_components', 'ERROR_INPUT')
            for component in profile['required_measured_components']:
                entry = measured.get(component)
                if not isinstance(entry, dict):
                    unavailable('R05', 'measurement_entry_dependency_unavailable', up + '.measured_components.entry')
                    continue
                equal(entry.get('component_id'), component, up + '.measured_components.entry.component_id', 'R05', 'measured_component_id_conflict')
                for field in ('version', 'digest'):
                    target = artifacts.get(component) if isinstance(artifacts, dict) else None
                    equal(entry.get(field), target.get(field) if isinstance(target, dict) else None,
                          up + '.measured_components.entry.' + field, 'R05', 'usage_artifact_conflict',
                          typed=hash_value if field == 'digest' else ident, trusted=uok and signed(record))
                    committed = cb.get('artifacts')
                    target = committed.get(component) if isinstance(committed, dict) else None
                    equal(entry.get(field), target.get(field) if isinstance(target, dict) else None,
                          up + '.measured_components.entry.' + field, 'R05', 'usage_commitment_artifact_conflict',
                          typed=hash_value if field == 'digest' else ident, trusted=uok and cok)
        else:
            unavailable('R05', 'measurement_dependency_unavailable', up + '.measured_components')
        order(resolution.get('issued_at'), ub.get('issued_at'), up + '.issued_at', 'R07', 'resolution_use_order', trusted=signed(resolution) and uok)
        order(ub.get('issued_at'), cb.get('issued_at'), cp + '.issued_at', 'R07', 'use_commit_order', trusted=uok and cok)
        order(cb.get('issued_at'), rb.get('issued_at'), xp + '.issued_at', 'R07', 'commit_release_order', strict=True, trusted=cok and rok)
        order(rb.get('issued_at'), record.get('issued_at'), path + '.issued_at', 'R07', 'release_exposure_order', trusted=rok and signed(record))
        use_seq, commit_seq, release_seq = ub.get('sequence'), cb.get('sequence'), rb.get('sequence')
        for left, right, trust, strict, bp in ((use_seq, commit_seq, uok and cok, False, cp),
                                               (commit_seq, release_seq, cok and rok, True, xp)):
            if trust and integer(left) and integer(right):
                if not (left < right if strict else left <= right):
                    add('R07', 'observed_sequence_order', bp + '.sequence')
            else:
                unavailable('R07', 'sequence_dependency_unavailable', bp + '.sequence')
    for record, path in groups['outcome']:
        p = payload(record)
        domain(p.get('attributed_condition'), profile['conditions'], path + '.payload.attributed_condition', 'R02', 'condition_domain')
        equal(p.get('attributed_condition'), payload(exposure).get('enacted_condition'), path + '.payload.attributed_condition', 'R07', 'outcome_condition_binding', trusted=signed(record) and signed(exposure))
        equal(p.get('exposure_record_id'), exposure.get('record_id'), path + '.payload.exposure_record_id', 'R07', 'outcome_exposure_id', trusted=signed(record) and signed(exposure))
        equal(p.get('exposure_digest'), dg(exposure), path + '.payload.exposure_digest', 'R07', 'outcome_exposure_digest', typed=hash_value, trusted=signed(record) and signed(exposure))
        if ident(p.get('consent_state')) and p['consent_state'] != 'consented':
            add('R06', 'consent_state_not_eligible', path + '.payload.consent_state')
        if type(p.get('eligible')) is bool and not p['eligible']:
            add('R06', 'outcome_not_eligible', path + '.payload.eligible')
        domain(p.get('purpose'), profile['permitted_purposes'], path + '.payload.purpose', 'R06', 'purpose_not_permitted')
        domain(p.get('consent_authority_ref'), profile['consent_authority_refs'], path + '.payload.consent_authority_ref', 'R06', 'consent_authority_not_permitted')
        equal(p.get('consent_policy_version'), profile['consent_policy_version'], path + '.payload.consent_policy_version', 'R06', 'consent_policy_conflict')
        ub, uok, _ = pinfo(exposure, 'usage_attestation')
        order(p.get('consent_at'), ub.get('issued_at'), path + '.payload.consent_at', 'R06', 'prospective_consent_order', trusted=signed(record) and uok)
    # Deterministic deduplication preserves all distinct defects while avoiding
    # repeated independent schema/integrity paths becoming misleading counts.
    return [dict(t) for t in dict.fromkeys(tuple(d.items()) for d in out)]
