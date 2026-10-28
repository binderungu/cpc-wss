"""Offline restricted JSON Schema mechanics, not a full Draft 2020-12 engine.

Only SUPPORTED_KEYWORDS and SUPPORTED_FORMATS execute. All schema definitions
and local references are checked before instance traversal. Remote references,
unknown keywords and unsupported keyword forms fail closed. Domain authority
belongs to the external profile and semantic evaluator, not condition enums.
"""
from __future__ import annotations
import json
import copy
import re
from pathlib import Path
from typing import Any
from .common import diagnostic, is_identifier, parse_time

SCHEMA_DIR = Path(__file__).resolve().parents[2] / 'schemas'
SUPPORTED_KEYWORDS = frozenset({'$schema', '$id', '$defs', '$ref', 'title',
    'description', 'type', 'properties', 'required', 'additionalProperties',
    'patternProperties', 'propertyNames', 'items', 'minItems', 'maxItems', 'minProperties',
    'minLength', 'maxLength', 'minimum', 'pattern', 'format', 'enum', 'const', 'anyOf'})
SUPPORTED_FORMATS = frozenset({'identifier', 'ascii-identifier', 'date-time', 'namespaced-key'})
_TYPES = {'object', 'array', 'string', 'integer', 'boolean', 'null'}
_NAME = re.compile(r'^[a-z][a-z0-9_]*\.json$')
_NAMESPACE = re.compile(r'^[A-Za-z][A-Za-z0-9_-]*(?:[.:][A-Za-z0-9_-]+)+$')
_ALIAS = {k:k+'_record' for k in ('assignment','resolution','exposure','outcome')}
_ALIAS.update({k+'_proof':k for k in ('launch_attestation','commitment','usage_attestation','release_attestation')})

class SchemaDefinitionError(ValueError):
    """Fixed messages never include instance content or schema-supplied strings."""


def _read_definitions():
    try:
        result = {p.name:json.loads(p.read_text(encoding='utf-8')) for p in sorted(SCHEMA_DIR.glob('*.json'))}
    except (ValueError, OSError, UnicodeError):
        raise SchemaDefinitionError('schema_definition_unreadable') from None
    if not result:
        raise SchemaDefinitionError('schema_definitions_absent')
    return result


def _resolve(reference, definitions, current):
    if not isinstance(reference, str):
        raise SchemaDefinitionError('schema_reference_invalid')
    filename, separator, pointer = reference.partition('#')
    if filename and (not _NAME.fullmatch(filename) or filename not in definitions):
        raise SchemaDefinitionError('schema_reference_unavailable')
    target = definitions[filename] if filename else current
    if separator and pointer:
        # Restricted local definition pointers only; no filesystem/URL traversal.
        if not re.fullmatch(r'/\$defs/[A-Za-z_][A-Za-z0-9_]*', pointer):
            raise SchemaDefinitionError('schema_reference_invalid')
        try:
            target = target['$defs'][pointer.split('/')[-1]]
        except (KeyError, TypeError):
            raise SchemaDefinitionError('schema_reference_unavailable') from None
    return target, definitions[filename] if filename else current


def _check_definition(schema, definitions, current):
    if not isinstance(schema, dict) or set(schema) - SUPPORTED_KEYWORDS:
        raise SchemaDefinitionError('schema_keyword_unsupported')
    for name in ('$schema', '$id', 'title', 'description'):
        if name in schema and not isinstance(schema[name], str):
            raise SchemaDefinitionError('schema_annotation_invalid')
    if '$schema' in schema and schema['$schema'] != 'https://json-schema.org/draft/2020-12/schema':
        raise SchemaDefinitionError('schema_dialect_unsupported')
    if '$id' in schema and not _NAME.fullmatch(schema['$id']):
        raise SchemaDefinitionError('schema_identifier_unsupported')
    if '$ref' in schema:
        _resolve(schema['$ref'], definitions, current)
    if 'type' in schema and schema['type'] not in _TYPES:
        raise SchemaDefinitionError('schema_type_unsupported')
    for name in ('minItems','maxItems','minProperties','minLength','maxLength','minimum'):
        if name in schema and (type(schema[name]) is not int or schema[name] < 0):
            raise SchemaDefinitionError('schema_bound_invalid')
    for name in ('minItems','minLength'):
        other = 'max'+name[3:]
        if name in schema and other in schema and schema[name] > schema[other]:
            raise SchemaDefinitionError('schema_bound_invalid')
    if 'required' in schema:
        value = schema['required']
        if not isinstance(value,list) or any(not isinstance(k,str) for k in value) or len(set(value)) != len(value):
            raise SchemaDefinitionError('schema_required_invalid')
    if 'format' in schema and schema['format'] not in SUPPORTED_FORMATS:
        raise SchemaDefinitionError('schema_format_unsupported')
    if 'pattern' in schema:
        _compile_pattern(schema['pattern'])
    if 'enum' in schema and (not isinstance(schema['enum'],list) or not schema['enum']):
        raise SchemaDefinitionError('schema_enum_invalid')
    for name in ('$defs','properties','patternProperties'):
        if name in schema:
            if not isinstance(schema[name],dict) or any(not isinstance(k,str) for k in schema[name]):
                raise SchemaDefinitionError('schema_children_invalid')
            for key, child in schema[name].items():
                if name == 'patternProperties': _compile_pattern(key)
                _check_definition(child, definitions, current)
    if 'additionalProperties' in schema:
        value = schema['additionalProperties']
        if type(value) is not bool:
            _check_definition(value, definitions, current)
    if 'items' in schema: _check_definition(schema['items'], definitions, current)
    if 'propertyNames' in schema: _check_definition(schema['propertyNames'], definitions, current)
    if 'anyOf' in schema:
        if not isinstance(schema['anyOf'],list) or not schema['anyOf']:
            raise SchemaDefinitionError('schema_branches_invalid')
        for child in schema['anyOf']: _check_definition(child, definitions, current)


def _compile_pattern(value):
    if not isinstance(value,str): raise SchemaDefinitionError('schema_pattern_invalid')
    try: return re.compile(value)
    except re.error: raise SchemaDefinitionError('schema_pattern_invalid') from None


def _check_all(definitions):
    for schema in definitions.values(): _check_definition(schema, definitions, schema)


def check_schema_definitions() -> list[dict]:
    """Definition/reference syntax check only, no CPC instance/conformance run."""
    try: _check_all(_read_definitions())
    except (SchemaDefinitionError, RecursionError, TypeError):
        return [diagnostic('C01','schema_definition_invalid','$schemas','ERROR_CONFIG')]
    return []


def _property_path(path, key):
    # Only trusted, simple schema property names appear verbatim in diagnostics.
    return path+'.'+key if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',key) else path+'[field]'


def _same(left,right):
    if type(left) is not type(right): return False
    if isinstance(left,dict): return left.keys()==right.keys() and all(_same(left[k],right[k]) for k in left)
    if isinstance(left,list): return len(left)==len(right) and all(_same(a,b) for a,b in zip(left,right))
    return left==right


def _evaluate(value,schema,path,definitions,current,ref_stack=()):
    errors=[]
    def err(code,at=path,rule='I02'): errors.append(diagnostic(rule,code,at,'ERROR_INPUT'))
    if '$ref' in schema:
        target, source = _resolve(schema['$ref'],definitions,current)
        marker=(id(target),id(value))
        if marker in ref_stack:
            err('schema_recursive_reference')
        else:
            errors.extend(_evaluate(value,target,path,definitions,source,ref_stack+(marker,)))
    if 'anyOf' in schema:
        branches=[_evaluate(value,s,path,definitions,current,ref_stack) for s in schema['anyOf']]
        if all(branches):
            # Preserve useful closed-field/type paths from the closest branch.
            best=min(branches,key=len)
            errors.extend(best)
            err('schema_any_of')
    expected=schema.get('type')
    match={'object':lambda:isinstance(value,dict) and all(isinstance(k,str) for k in value),
           'array':lambda:isinstance(value,list),'string':lambda:isinstance(value,str),
           'integer':lambda:type(value) is int,'boolean':lambda:type(value) is bool,
           'null':lambda:value is None}
    if expected and not match[expected]():
        err('schema_type'); return errors
    if 'const' in schema and not _same(value,schema['const']): err('schema_const','%s'%path,'I03')
    if 'enum' in schema and not any(_same(value,v) for v in schema['enum']): err('schema_enum',path,'I03')
    if isinstance(value,str):
        if 'minLength' in schema and len(value)<schema['minLength']: err('schema_min_length')
        if 'maxLength' in schema and len(value)>schema['maxLength']: err('schema_max_length')
        if 'pattern' in schema and not re.search(schema['pattern'],value): err('schema_pattern')
        form=schema.get('format')
        valid=(form is None or (form=='identifier' and is_identifier(value)) or
               (form=='ascii-identifier' and is_identifier(value) and value.isascii()) or
               (form=='date-time' and parse_time(value) is not None) or
               (form=='namespaced-key' and is_identifier(value) and _NAMESPACE.fullmatch(value)))
        if not valid: err('schema_format')
    if type(value) is int and 'minimum' in schema and value<schema['minimum']: err('schema_minimum')
    if isinstance(value,list):
        if 'minItems' in schema and len(value)<schema['minItems']: err('schema_min_items')
        if 'maxItems' in schema and len(value)>schema['maxItems']: err('schema_max_items')
        if 'items' in schema:
            for index,item in enumerate(value): errors.extend(_evaluate(item,schema['items'],f'{path}[{index}]',definitions,current,ref_stack))
    if isinstance(value,dict):
        if 'minProperties' in schema and len(value)<schema['minProperties']: err('schema_min_properties')
        if 'propertyNames' in schema:
            for key in value:
                errors.extend(_evaluate(key,schema['propertyNames'],path+'[field_name]',definitions,current,ref_stack))
        for key in schema.get('required',[]):
            if key not in value: err('schema_required',_property_path(path,key))
        properties=schema.get('properties',{})
        for key,item in value.items():
            children=[]
            if key in properties: children.append((properties[key],_property_path(path,key)))
            for pattern,child in schema.get('patternProperties',{}).items():
                if re.search(pattern,key): children.append((child,path+'[field]'))
            if not children:
                additional=schema.get('additionalProperties',True)
                if additional is False: err('schema_unknown_field',path+'[unknown]','I03')
                elif isinstance(additional,dict): children.append((additional,path+'[field]'))
            for child,childpath in children:
                errors.extend(_evaluate(item,child,childpath,definitions,current,ref_stack))
    return errors


def validate_instance(value: Any, schema: dict, path: str='$') -> list[dict]:
    try:
        definitions=_read_definitions(); _check_all(definitions)
        _check_definition(schema,definitions,schema)
        return _evaluate(value,schema,path,definitions,schema)
    except (SchemaDefinitionError, RecursionError, TypeError, ValueError, OverflowError):
        return [diagnostic('I02','schema_definition_or_structure_invalid',path,'ERROR_INPUT')]


def _identifier_bounds(definitions, maximum):
    """Apply frozen identifier length to structure, not encoded hashes/times."""
    if type(maximum) is not int or not 1 <= maximum <= 256:
        raise SchemaDefinitionError('identifier_bound_invalid')
    bounded = copy.deepcopy(definitions)
    def walk(schema):
        if not isinstance(schema, dict):
            return
        form = schema.get('format')
        pattern = schema.get('pattern', '')
        encoded_hash = isinstance(pattern, str) and pattern.startswith(('^sha256:', '^hmac-sha256:'))
        if form in {'identifier','ascii-identifier','namespaced-key'} and not encoded_hash:
            schema['maxLength'] = min(schema.get('maxLength',256), maximum)
        for key in ('$defs','properties','patternProperties'):
            for child in schema.get(key, {}).values():
                walk(child)
        if isinstance(schema.get('additionalProperties'),dict):
            walk(schema['additionalProperties'])
        if isinstance(schema.get('items'),dict):
            walk(schema['items'])
        if isinstance(schema.get('propertyNames'),dict):
            walk(schema['propertyNames'])
        for child in schema.get('anyOf',[]):
            walk(child)
    for schema in bounded.values():
        walk(schema)
    return bounded

def validate_named(value: Any, name: str, path: str='$', *, max_identifier_chars: int=256) -> list[dict]:
    try:
        definitions=_read_definitions(); _check_all(definitions)
        definitions=_identifier_bounds(definitions,max_identifier_chars)
        filename=_ALIAS.get(name,name)+'.json'
        if filename not in definitions: raise SchemaDefinitionError('schema_name_unavailable')
        schema=definitions[filename]
        return _evaluate(value,schema,path,definitions,schema)
    except (SchemaDefinitionError, RecursionError, TypeError, ValueError, OverflowError):
        return [diagnostic('I02','schema_definition_or_structure_invalid',path,'ERROR_INPUT')]
