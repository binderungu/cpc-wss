"""Strict admission boundary and batch accounting; no fixture execution on import."""
from __future__ import annotations
import hashlib
import json
import uuid
from typing import Iterable
from .common import diagnostic, is_identifier, iter_json_nodes, CONTRACT_VERSION
from .profile import validate_profile
from .schema import validate_named
from .validator import validate_chain

PRECEDENCE = {'REJECT': 0, 'ERROR_INPUT': 1, 'QUARANTINE': 2, 'ADMIT': 3}
ROOT_FIELDS = {'contract_version', 'profile_id', 'profile_version', 'case_id', 'records'}

def final_disposition(diagnostics: list[dict]) -> str:
    relevant = [d['disposition'] for d in diagnostics if d['disposition'] in PRECEDENCE]
    if relevant:
        return min(relevant, key=PRECEDENCE.__getitem__)
    return 'ERROR_INPUT' if any(d['disposition'] == 'NOT_EVALUABLE' for d in diagnostics) else 'ADMIT'

def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key] = value
    return result

def _nonfinite(value):
    raise ValueError('nonfinite_json_number')

def _wire_scan(value, max_depth):
    errors = []
    for current, depth in iter_json_nodes(value):
        if depth > max_depth:
            return [diagnostic('I01', 'input_depth_limit', '$', 'ERROR_INPUT')]
        if isinstance(current, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in current):
                errors.append(diagnostic('I01', 'invalid_unicode_scalar', '$', 'ERROR_INPUT'))
        elif current is None or type(current) is bool:
            pass
        elif type(current) is int:
            if current < 0:
                errors.append(diagnostic('I01', 'negative_wire_integer', '$', 'ERROR_INPUT'))
        elif isinstance(current, float):
            errors.append(diagnostic('I01', 'floating_wire_number', '$', 'ERROR_INPUT'))
        elif isinstance(current, (list, dict)):
            pass
        else:
            errors.append(diagnostic('I01', 'unsupported_wire_value', '$', 'ERROR_INPUT'))
    return errors

def _new_ref(maximum=256):
    return ('input-' + uuid.uuid4().hex)[:maximum]

def _base(raw_bytes, input_ref, profile):
    profile_id = profile.get('profile_id') if isinstance(profile, dict) else None
    profile_version = profile.get('profile_version') if isinstance(profile, dict) else None
    return {'input_ref': input_ref, 'input_sha256': 'sha256:' + hashlib.sha256(raw_bytes).hexdigest(),
            'case_id': None, 'contract_version': CONTRACT_VERSION,
            'profile_id': profile_id if is_identifier(profile_id) else None,
            'profile_version': profile_version if is_identifier(profile_version) else None,
            'disposition': 'ERROR_INPUT', 'diagnostics': [], 'admitted_record': None}

def _normalize(chain, input_ref):
    # This function is reached only after structural and semantic admission.
    by = {record['record_type']: record for record in chain['records']}
    exposure = by['exposure']; outcome = by['outcome']
    return {'input_ref': input_ref, 'case_id': chain['case_id'],
            'experiment_id': exposure['experiment_id'], 'experiment_version': exposure['experiment_version'],
            'unit_token': exposure['unit_token'], 'attributed_condition': outcome['payload']['attributed_condition'],
            'artifact_version': exposure['payload']['artifact_version'],
            'exposure_record_id': exposure['record_id'],
            'exposure_digest': exposure['integrity']['content_digest'],
            'outcome_key': outcome['payload']['outcome_key'], 'purpose': outcome['payload']['purpose']}

def validate_raw(raw: str | bytes, profile: dict, key_registry: dict, validation_time: str,
                 *, input_ref: str | None = None) -> dict:
    """Validate raw UTF-8 under a separately supplied operator trust context.

    Python argument misuse is outside the wire protocol and raises TypeError.
    Every str/bytes input is accounted, including malformed wire input/config.
    This API cannot establish the truth of capture/observer assertions (D2).
    """
    if not isinstance(raw, (str, bytes)):
        raise TypeError('raw must be str or bytes; no implicit object serialization')
    invalid_utf8 = False
    try:
        data = raw.encode('utf-8') if isinstance(raw, str) else raw
    except UnicodeEncodeError:
        # There are no valid UTF-8 bytes to fingerprint; retain a hash of the
        # unencodable transport representation without mislabelling it UTF-8.
        data = raw.encode('utf-8', errors='surrogatepass')
        invalid_utf8 = True
    config_errors = validate_profile(profile, validation_time, key_registry)
    maximum = profile['input_limits']['max_identifier_chars'] if not config_errors else 256
    ref = _new_ref(maximum) if input_ref is None else input_ref
    if not is_identifier(ref, maximum):
        raise ValueError('operator input_ref invalid')
    result = _base(data, ref, profile)
    if config_errors:
        result['disposition'] = 'ERROR_CONFIG'; result['diagnostics'] = config_errors
        return result
    if invalid_utf8:
        result['diagnostics'] = [diagnostic('I01', 'invalid_utf8_transport', '$', 'ERROR_INPUT')]
        return result
    limits = profile['input_limits']
    if len(data) > limits['max_bytes']:
        result['diagnostics'] = [diagnostic('I01', 'input_byte_limit', '$', 'ERROR_INPUT')]
        return result
    try:
        chain = json.loads(data.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        result['diagnostics'] = [diagnostic('I01', 'input_decode_failed', '$', 'ERROR_INPUT')]
        return result
    # Shallow routing bookkeeping does not decide structural/semantic validity.
    if isinstance(chain, dict) and is_identifier(chain.get('case_id'), limits['max_identifier_chars']):
        result['case_id'] = chain['case_id']
    wire_errors = _wire_scan(chain, limits['max_depth'])
    if any(d['code'] == 'input_depth_limit' for d in wire_errors):
        result['diagnostics'] = wire_errors
        return result
    if not isinstance(chain, dict):
        result['diagnostics'] = wire_errors + [diagnostic('I01', 'input_root_not_object', '$', 'ERROR_INPUT')]
        return result
    shape_errors = validate_named(chain, 'chain', max_identifier_chars=limits['max_identifier_chars'])
    if isinstance(chain, dict) and isinstance(chain.get('records'), list) and len(chain['records']) > limits['max_records']:
        result['diagnostics'] = wire_errors + [diagnostic('I01', 'record_count_limit', '$.records', 'ERROR_INPUT')]
        return result
    # Shape errors do not hide safe independent contradictions in other records.
    semantic = validate_chain(chain, profile, key_registry, validation_time) if isinstance(chain, dict) else []
    all_errors = wire_errors + shape_errors + semantic
    if (any(d['disposition'] == 'NOT_EVALUABLE' for d in all_errors)
            and not any(d['disposition'] in PRECEDENCE for d in all_errors)):
        all_errors.append(diagnostic('I02', 'required_relation_not_evaluable', '$', 'ERROR_INPUT'))
    unique = {(d['rule_id'], d['code'], d['path'], d['disposition']): d for d in all_errors}
    result['diagnostics'] = [unique[key] for key in sorted(unique)]
    result['disposition'] = final_disposition(result['diagnostics'])
    if result['disposition'] == 'ADMIT':
        # Defensive export guard: shape validation of the normalized result is
        # part of admission, never a post-admission indexing exception.
        normalized = _normalize(chain, ref)
        export_errors = validate_named(normalized, 'admitted_export', max_identifier_chars=limits['max_identifier_chars'])
        if export_errors:
            raise RuntimeError('implementation produced structurally invalid admitted export')
        result['admitted_record'] = normalized
    return result

def validate_batch(raw_inputs: Iterable[str | bytes], profile: dict, key_registry: dict,
                   validation_time: str) -> list[dict]:
    batch_id = uuid.uuid4().hex
    config_errors = validate_profile(profile,validation_time,key_registry)
    maximum = profile['input_limits']['max_identifier_chars'] if not config_errors else 256
    def ref(index):
        suffix = '-'+str(index)
        if len(suffix) >= maximum:
            raise ValueError('batch identifier capacity exceeded')
        return ('input-'+batch_id)[:maximum-len(suffix)]+suffix
    results = [validate_raw(raw, profile, key_registry, validation_time,
                            input_ref=ref(index)) for index, raw in enumerate(raw_inputs)]
    seen = set()
    for result in results:
        case_id = result['case_id']
        if case_id is not None and case_id in seen:
            result['diagnostics'].append(diagnostic('BATCH', 'duplicate_case_id_metadata', '$.case_id', 'INFO'))
        if case_id is not None:
            seen.add(case_id)
    return results
