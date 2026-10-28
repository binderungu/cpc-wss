"""Fixture-only digest/HMAC verification; never observes artifact consumption.

verify_record/verify_proof return (verified, diagnostics). False is a dependency
failure, never a successful comparison. Trusted registry material comes solely
from the caller, separately from the input and the immutable operator profile.
"""
from __future__ import annotations

import hashlib
import hmac

from .common import (DIGEST_RE, MAC_RE,
                     diagnostic, digest, is_identifier)


def _verify(value, signed, expected_issuer, profile, key_registry, path, proof_body=False):
    errors = []
    def add(rule, code, suffix, disposition):
        errors.append(diagnostic(rule, code, path + suffix, disposition))
    if not isinstance(value, dict) or not isinstance(signed, dict):
        add('I02', 'signed_object_unavailable', '', 'ERROR_INPUT')
        return False, errors
    actual_issuer = signed.get('issuer')
    issuer_suffix = '.body.issuer' if proof_body else '.issuer'
    if is_identifier(actual_issuer) and is_identifier(expected_issuer):
        if actual_issuer != expected_issuer:
            add('R01', 'unauthorized_issuer', issuer_suffix, 'REJECT')
    else:
        add('I02', 'issuer_unavailable', issuer_suffix, 'ERROR_INPUT')
    envelope = value.get('integrity')
    if not isinstance(envelope, dict):
        add('I02', 'integrity_unavailable', '.integrity', 'ERROR_INPUT')
        return False, errors
    algorithm = envelope.get('algorithm')
    key_id = envelope.get('key_id')
    supplied_digest = envelope.get('content_digest')
    supplied_mac = envelope.get('mac')
    if not is_identifier(algorithm):
        add('I02', 'algorithm_unavailable', '.integrity.algorithm', 'ERROR_INPUT')
    elif algorithm != 'HMAC-SHA256':
        add('R01', 'unsupported_algorithm', '.integrity.algorithm', 'REJECT')
    if not is_identifier(key_id) or not key_id.isascii():
        add('I02', 'key_id_encoding', '.integrity.key_id', 'ERROR_INPUT')
    if not isinstance(supplied_digest, str) or not DIGEST_RE.fullmatch(supplied_digest):
        add('I02', 'digest_encoding', '.integrity.content_digest', 'ERROR_INPUT')
    if not isinstance(supplied_mac, str) or not MAC_RE.fullmatch(supplied_mac):
        add('I02', 'mac_encoding', '.integrity.mac', 'ERROR_INPUT')
    permitted = profile.get('issuer_key_policy', {}).get(expected_issuer)
    key_authorized = (is_identifier(key_id) and key_id.isascii()
                      and key_id == permitted and key_id in key_registry)
    if is_identifier(key_id) and key_id.isascii() and not key_authorized:
        add('R01', 'unauthorized_key_relationship', '.integrity.key_id', 'REJECT')
    try:
        computed = digest(signed)
    except (ValueError, TypeError, UnicodeEncodeError, RecursionError):
        add('I02', 'unsupported_signed_wire_value', '', 'ERROR_INPUT')
        add('R01', 'signature_dependency_unavailable', '', 'NOT_EVALUABLE')
        return False, errors
    digest_wellformed = isinstance(supplied_digest, str) and bool(DIGEST_RE.fullmatch(supplied_digest))
    if digest_wellformed and not hmac.compare_digest(computed, supplied_digest):
        add('R01', 'content_digest_mismatch', '.integrity.content_digest', 'REJECT')
    mac_wellformed = isinstance(supplied_mac, str) and bool(MAC_RE.fullmatch(supplied_mac))
    if key_authorized and digest_wellformed and mac_wellformed:
        key = key_registry[key_id]
        if not isinstance(key, (str, bytes)) or not key.isascii() or not key:
            # The outer runner validates trusted key configuration; retain a
            # safe dependency result if a caller bypasses that boundary.
            add('R01', 'trusted_key_unavailable', '.integrity.key_id', 'NOT_EVALUABLE')
        else:
            key_bytes = key.encode('ascii') if isinstance(key, str) else key
            expected = 'hmac-sha256:' + hmac.new(key_bytes, supplied_digest.encode('ascii'), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, supplied_mac):
                add('R01', 'mac_mismatch', '.integrity.mac', 'REJECT')
    return not errors, errors


def verify_record(record, profile, key_registry, path='$'):
    """Record signature covers all record fields except top-level integrity."""
    kind = record.get('record_type') if isinstance(record, dict) else None
    expected = profile.get('record_issuers', {}).get(kind) if isinstance(kind, str) else None
    signed = {k: v for k, v in record.items() if k != 'integrity'} if isinstance(record, dict) else None
    return _verify(record, signed, expected, profile, key_registry, path)


def verify_proof(proof, proof_kind, profile, key_registry, path='$'):
    """Proof signature covers body; complete-proof digest is a separate link."""
    signed = proof.get('body') if isinstance(proof, dict) else None
    expected = profile.get('proof_issuers', {}).get(proof_kind) if isinstance(proof_kind, str) else None
    return _verify(proof, signed, expected, profile, key_registry, path, proof_body=True)
