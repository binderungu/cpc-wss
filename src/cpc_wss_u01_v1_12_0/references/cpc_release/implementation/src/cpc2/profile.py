"""Fail-closed external frozen-profile checks; no profiles or keys are created.

Wire schemas separate malformed fields from semantic domains. This module
checks operator configuration only and never derives a profile from a chain.
"""
from __future__ import annotations
import re
from .common import diagnostic, is_identifier, parse_time, CONTRACT_VERSION, SCHEMA_VERSION
from .schema import validate_named

COMPONENTS = frozenset({'prompt','generation','ui','corpus','retriever','index','model','policy'})
MEASURED = frozenset({'prompt','generation'})
LIMITS = {'max_bytes':1048576,'max_records':16,'max_depth':32,'max_identifier_chars':256}
CANONICALIZATIONS = {'prompt':'raw-bytes consumed','generation':'cpc-json-v2 object consumed'}


def normalize_privacy_leaf(value):
    return ''.join(c for c in value.casefold() if c.isalnum())


def validate_profile(profile, validation_time, key_registry) -> list[dict]:
    """Return C01 ERROR_CONFIG only. Trusted profile/keys/time supplied separately."""
    errors=[]
    def fail(code,path='$profile'):
        errors.append(diagnostic('C01',code,path,'ERROR_CONFIG'))
    shape=validate_named(profile,'profile',path='$profile')
    if shape:
        return [diagnostic('C01','profile_'+d['code'],d['path'],'ERROR_CONFIG') for d in shape]
    now=parse_time(validation_time)
    frozen=parse_time(profile['freeze_timestamp'])
    if now is None: fail('validation_time_invalid','$context.validation_time')
    if profile['profile_state'] != 'frozen': fail('profile_not_frozen','$profile.profile_state')
    if frozen is None or (now is not None and frozen>now): fail('profile_freeze_time_invalid','$profile.freeze_timestamp')
    if profile['contract_version'] != CONTRACT_VERSION: fail('profile_contract_unsupported','$profile.contract_version')
    if profile['schema_version'] != SCHEMA_VERSION: fail('profile_schema_unsupported','$profile.schema_version')
    if profile['release_boundary'] != 'durable_local_response_file': fail('profile_release_boundary_unsupported','$profile.release_boundary')
    conditions=profile['conditions']; domains=set(conditions)
    if len(domains)!=len(conditions): fail('profile_conditions_duplicate','$profile.conditions')
    for raw,condition in profile['resource_condition_map'].items():
        if not is_identifier(raw): fail('profile_resource_identifier_invalid','$profile.resource_condition_map[field]')
        if condition not in domains: fail('profile_resource_condition_unauthorized','$profile.resource_condition_map[field]')
    authoritative=False
    for name,policy in profile['namespace_policy'].items():
        path='$profile.namespace_policy[field]'
        if not is_identifier(name) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*(?:[.:][A-Za-z0-9_-]+)+',name):
            fail('profile_namespace_identifier_invalid',path)
        role=policy['role']; mapping=policy['mapping']
        if role not in {'authoritative','consistency','descriptive'}: fail('profile_namespace_role_unsupported',path+'.role')
        if role=='authoritative' and policy['required']: authoritative=True
        if role=='descriptive':
            if mapping: fail('profile_descriptive_mapping_forbidden',path+'.mapping')
            if policy['required']: fail('profile_descriptive_authority_forbidden',path+'.required')
        elif role in {'authoritative','consistency'}:
            if not mapping: fail('profile_namespace_mapping_absent',path+'.mapping')
            for raw,condition in mapping.items():
                if not is_identifier(raw): fail('profile_namespace_raw_identifier_invalid',path+'.mapping[field]')
                if condition not in domains: fail('profile_namespace_condition_unauthorized',path+'.mapping[field]')
    if not authoritative: fail('profile_required_authority_absent','$profile.namespace_policy')
    for name in ('permitted_purposes','consent_authority_refs','extension_keys','privacy_denylist','required_measured_components'):
        if len(set(profile[name]))!=len(profile[name]): fail('profile_policy_duplicate','$profile.'+name)
    if set(profile['required_measured_components']) != MEASURED:
        fail('profile_measured_components_unsupported','$profile.required_measured_components')
    if profile['component_canonicalizations'] != CANONICALIZATIONS:
        fail('profile_canonicalizations_unsupported','$profile.component_canonicalizations')
    for bundle,vector in profile['artifact_registry'].items():
        if not is_identifier(bundle): fail('profile_bundle_identifier_invalid','$profile.artifact_registry[field]')
        if set(vector)!=COMPONENTS: fail('profile_component_set_invalid','$profile.artifact_registry[field]')
        for component,entry in vector.items():
            mode='measured' if component in MEASURED else 'declared'
            if entry['evidence_mode'] != mode:
                fail('profile_component_evidence_mode_invalid','$profile.artifact_registry[field][field].evidence_mode')
    for reference,permission in profile['fallback_permissions'].items():
        path='$profile.fallback_permissions[field]'
        if not is_identifier(reference): fail('profile_fallback_identifier_invalid',path)
        if permission['condition'] not in domains: fail('profile_fallback_condition_unauthorized',path+'.condition')
        versions=permission['artifact_versions']
        if len(set(versions))!=len(versions): fail('profile_fallback_versions_duplicate',path+'.artifact_versions')
        if any(version not in profile['artifact_registry'] for version in versions):
            fail('profile_fallback_bundle_unauthorized',path+'.artifact_versions')
    for leaf in profile['privacy_denylist']:
        if leaf != normalize_privacy_leaf(leaf) or not leaf:
            fail('profile_privacy_leaf_not_normalized','$profile.privacy_denylist[field]')
    limits=profile['input_limits']
    for name,maximum in LIMITS.items():
        if limits[name]>maximum: fail('profile_input_limit_unsupported','$profile.input_limits.'+name)
    # The contract permits stricter positive operator bounds. A configuration
    # need not accommodate an ADMIT chain; overflow belongs to the input
    # boundary, not a fabricated configuration error.
    # Every policy identifier/map key must fit this profile's own frozen bound.
    maximum=limits['max_identifier_chars']
    def inspect_identifiers(value,path):
        if isinstance(value,str) and (len(value)>maximum): fail('profile_identifier_limit_inconsistent',path)
        elif isinstance(value,list):
            for item in value: inspect_identifiers(item,path+'[item]')
        elif isinstance(value,dict):
            for key,item in value.items():
                if len(key)>maximum: fail('profile_identifier_limit_inconsistent',path+'[field]')
                inspect_identifiers(item,path+'[field]')
    # Digests/times/canonicalization labels are not identifiers, so inspect
    # identifier-bearing fields rather than every string in the profile.
    non_ids={'freeze_timestamp','artifact_registry','input_limits','component_canonicalizations'}
    for name,value in profile.items():
        if name not in non_ids: inspect_identifiers(value,'$profile.'+name)
    for bundle,vector in profile['artifact_registry'].items():
        if len(bundle)>maximum: fail('profile_identifier_limit_inconsistent','$profile.artifact_registry[field]')
        for entry in vector.values():
            if len(entry['version'])>maximum: fail('profile_identifier_limit_inconsistent','$profile.artifact_registry[field][field].version')
    issuers=profile['record_issuers']; proofs=profile['proof_issuers']; policy=profile['issuer_key_policy']
    if proofs['launch_attestation']!=issuers['assignment']:
        fail('profile_launch_authority_inconsistent','$profile.proof_issuers.launch_attestation')
    if proofs['usage_attestation']!=proofs['release_attestation']:
        fail('profile_observer_authority_inconsistent','$profile.proof_issuers')
    role_issuers=[issuers['assignment'],issuers['resolution'],proofs['commitment'],issuers['outcome'],proofs['usage_attestation']]
    if proofs['commitment']!=issuers['exposure']:
        fail('profile_runtime_authority_inconsistent','$profile.proof_issuers.commitment')
    used=set(issuers.values())|set(proofs.values())
    if set(policy)!=used: fail('profile_issuer_policy_set_invalid','$profile.issuer_key_policy')
    for issuer in policy:
        if not is_identifier(issuer): fail('profile_issuer_identifier_invalid','$profile.issuer_key_policy[field]')
    role_keys=[policy.get(issuer) for issuer in role_issuers]
    if any(key is None for key in role_keys): fail('profile_role_key_absent','$profile.issuer_key_policy')
    elif len(set(role_keys))!=5: fail('profile_logical_role_keys_not_distinct','$profile.issuer_key_policy')
    if not isinstance(key_registry,dict):
        fail('profile_key_registry_invalid','$key_registry')
    else:
        for key_id in set(policy.values()):
            material=key_registry.get(key_id)
            if isinstance(material,str):
                try: material=material.encode('ascii')
                except UnicodeError: material=None
            if (not isinstance(material,bytes) or not material.startswith(b'SYNTHETIC_ONLY_')
                    or len(material)<=len(b'SYNTHETIC_ONLY_') or not material.isascii()
                    or any(byte<33 or byte>126 for byte in material)):
                fail('profile_synthetic_key_material_invalid','$key_registry[field]')
    return errors
