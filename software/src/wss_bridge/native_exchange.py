"""Bounded local operation exchange; never opens a native source or launches IO.

The runner process keeps its offline guard. A separately authorized coordinator
may service an already durable operation request in another process. Files and
process fields are supplied evidence, not source-truth or authority attestations.
Storage assumes cooperating single writers on one POSIX host, not hostile peers.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
from pathlib import Path
import time
from collections.abc import Mapping

from .ledger import _real_directory, _new_file, _read_file, _fsync_directory
from .primitives import (canonical_json_bytes, decode_json_object, plain_json,
                         require_identifier, require_int, require_digest)
from .worked_runner import OperationRequest, OperationInput, ObservationInput
from .native_transport import MAX_TRANSPORT_BYTES

MAX_RAW_BYTES = 64 * 1024 * 1024
MAX_REQUEST_BYTES = 128 * 1024
MAX_PROCESS_BYTES = 128 * 1024
MAX_RESPONSE_BYTES = 3 * (4 * ((MAX_TRANSPORT_BYTES + 2) // 3)) + MAX_PROCESS_BYTES + 8192
FORMAT = 'wss-local-operation-exchange-v1'


class ExchangeStopped(RuntimeError):
    """Retain all files; no retry or continued operation is authorized."""


def _sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _checked(condition, message):
    if not condition:
        raise ExchangeStopped(message)


def _integer(value, name, low=0, high=2**63-1):
    _checked(type(value) is int and low <= value <= high, name + ': invalid integer')
    return value


def _atomic_file(path, raw):
    """Only used in a newly exclusive single-writer message directory."""
    _real_directory(path.parent, exists=True)
    _checked(not path.exists() and not path.is_symlink(), 'message destination exists')
    temp = path.with_name(path.name + '.staging')
    _new_file(temp, raw)
    # The message directory has one cooperating owner. No overwrite recovery is
    # supported; a leftover staging file is a retained incomplete publication.
    _checked(not path.exists() and not path.is_symlink(), 'message destination changed')
    os.rename(temp, path)
    _fsync_directory(path.parent)


def _publish(directory, payload, maximum):
    raw = canonical_json_bytes(payload)
    _checked(len(raw) <= maximum, 'message byte bound exceeded')
    _real_directory(directory, exists=False)
    directory.mkdir(mode=0o700)
    _fsync_directory(directory.parent)
    _atomic_file(directory / 'payload.json', raw)
    _atomic_file(directory / 'READY.json', canonical_json_bytes({
        'format': FORMAT, 'bytes': len(raw), 'sha256': _sha(raw)}))
    return _sha(raw)


def _message(directory, maximum):
    if not directory.exists() and not directory.is_symlink():
        return None
    _real_directory(directory, exists=True)
    ready = directory / 'READY.json'
    if not ready.exists() and not ready.is_symlink():
        return None
    marker = decode_json_object(_read_file(ready, 1024), 'exchange ready')
    _checked(set(marker) == {'format', 'bytes', 'sha256'} and marker['format'] == FORMAT,
             'invalid ready marker')
    _integer(marker['bytes'], 'message bytes', 1, maximum)
    raw = _read_file(directory / 'payload.json', maximum)
    _checked(len(raw) == marker['bytes'] and _sha(raw) == marker['sha256'],
             'message hash or length differs')
    value = decode_json_object(raw, 'exchange payload')
    _checked(canonical_json_bytes(value) == raw, 'noncanonical exchange payload')
    return value, _sha(raw)


def create_exchange(root, run_ref, *, max_operations=6, max_observations=18,
                    max_raw_bytes=MAX_RAW_BYTES, timeout_seconds=60.0,
                    poll_interval=0.01):
    """Create an unused exclusive channel. This supplies no native permission."""
    require_identifier(run_ref, 'exchange.run_ref')
    _integer(max_operations, 'max_operations', 1, 200)
    _integer(max_observations, 'max_observations', 1, 600)
    _integer(max_raw_bytes, 'max_raw_bytes', 1, MAX_RAW_BYTES)
    for value, name, low, high in ((timeout_seconds, 'timeout_seconds', .01, 120),
                                  (poll_interval, 'poll_interval', .001, 1)):
        _checked(type(value) in (int, float) and math.isfinite(value) and low <= value <= high,
                 name + ': invalid bound')
    _checked(poll_interval <= timeout_seconds, 'poll interval exceeds timeout')
    root = _real_directory(root, exists=False)
    root.mkdir(mode=0o700)
    for name in ('requests', 'responses', 'receipts'):
        (root / name).mkdir(mode=0o700)
    meta = {'format': FORMAT, 'run_ref': run_ref, 'max_operations': max_operations,
            'max_observations': max_observations, 'max_raw_bytes': max_raw_bytes,
            'timeout_ns': round(timeout_seconds * 1_000_000_000), 'poll_interval_ns': round(poll_interval * 1_000_000_000),
            'authority': 'EXTERNAL_OWNER_SCOPE_REQUIRED',
            'trust': 'COOPERATING_SINGLE_WRITERS_SAME_POSIX_HOST'}
    _atomic_file(root / 'exchange.json', canonical_json_bytes(meta))
    _fsync_directory(root.parent)
    return root


def _metadata(root):
    root = _real_directory(root, exists=True)
    for name in ('requests', 'responses', 'receipts'):
        _real_directory(root / name, exists=True)
    raw = _read_file(root / 'exchange.json', 4096)
    meta = decode_json_object(raw, 'exchange metadata')
    _checked(meta.get('format') == FORMAT, 'exchange format differs')
    require_identifier(meta['run_ref'], 'exchange.run_ref')
    _integer(meta['max_operations'], 'max_operations', 1, 200)
    _integer(meta['max_observations'], 'max_observations', 1, 600)
    _integer(meta['max_raw_bytes'], 'max_raw_bytes', 1, MAX_RAW_BYTES)
    _integer(meta['timeout_ns'], 'timeout_ns', 10_000_000, 120_000_000_000)
    _integer(meta['poll_interval_ns'], 'poll_interval_ns', 1_000_000, 1_000_000_000)
    _checked(meta['poll_interval_ns'] <= meta['timeout_ns'], 'exchange timing differs')
    _checked(canonical_json_bytes(meta) == raw, 'noncanonical exchange metadata')
    return root, meta, _sha(raw)


def _ordinal(meta, ordinal):
    return _integer(ordinal, 'ordinal', 1, meta['max_operations'])


def _request(root, meta, ordinal, *, allow_expired=False):
    _ordinal(meta, ordinal)
    message = _message(root / 'requests' / str(ordinal).zfill(3), MAX_REQUEST_BYTES)
    if message is None:
        return None
    value, digest = message
    _checked(set(value) == {'format', 'run_ref', 'ordinal', 'metadata_sha256',
             'created_monotonic_ns', 'deadline_monotonic_ns', 'operation'}, 'request shape differs')
    _, _, metadata_digest = _metadata(root)
    _checked(value['format'] == FORMAT and value['run_ref'] == meta['run_ref']
             and value['ordinal'] == ordinal and value['metadata_sha256'] == metadata_digest,
             'request channel identity differs')
    _integer(value['created_monotonic_ns'], 'request created', 1)
    _integer(value['deadline_monotonic_ns'], 'request deadline', value['created_monotonic_ns'] + 1)
    _checked(value['deadline_monotonic_ns'] - value['created_monotonic_ns']
             == meta['timeout_ns'], 'request deadline bound differs')
    if not allow_expired:
        _checked(time.monotonic_ns() <= value['deadline_monotonic_ns'], 'operation request expired')
        _checked(not (root / 'receipts' / (str(ordinal).zfill(3) + '.timeout.json')).exists(),
                 'operation consumer timed out')
    op = value['operation']
    _checked(type(op) is dict and set(op) == {'episode_ref', 'kind', 'operation_ref',
             'attempt_ref', 'log_watermark', 'controlled_value_digest', 'context'}, 'operation shape differs')
    for key in ('episode_ref', 'operation_ref'):
        require_identifier(op[key], key)
    _checked(op['kind'] in ('TASK', 'FOLLOWUP'), 'operation kind differs')
    if op['attempt_ref'] is not None:
        require_identifier(op['attempt_ref'], 'attempt_ref')
    _integer(op['log_watermark'], 'log_watermark')
    require_digest(op['controlled_value_digest'], 'controlled_value_digest')
    _checked(type(op['context']) is dict, 'operation context missing')
    return value, digest


def read_request(root, ordinal):
    """Read a complete unexpired request, or None. Never claims/executes an op.

    The coordinator must independently verify grant/current context and durably
    charge actual native actions. Reading this file is not a native authorization.
    """
    root, meta, _ = _metadata(root)
    result = _request(root, meta, ordinal)
    if result is None:
        return None
    value, digest = result
    return {**value, 'request_sha256': digest}


def _input_mapping(value):
    _checked(type(value) is OperationInput, 'typed OperationInput required')
    return {'completion_known': value.completion_known,
            'completion_evidence_ref': value.completion_evidence_ref,
            'observations': [{'slot_ms': o.slot_ms, 'raw_b64': base64.b64encode(o.raw).decode('ascii'),
                              'raw_sha256': _sha(o.raw), 'raw_bytes': len(o.raw),
                              'reported_exit_code': o.reported_exit_code,
                              'reported_close_confirmed': o.reported_close_confirmed}
                             for o in value.observations]}


def _decode_input(value):
    _checked(type(value) is dict and set(value) == {'completion_known', 'completion_evidence_ref', 'observations'},
             'response input shape differs')
    observations = value['observations']
    _checked(type(observations) is list and len(observations) <= 3, 'observation count exceeds bound')
    decoded = []
    for i, row in enumerate(observations):
        _checked(type(row) is dict and set(row) == {'slot_ms', 'raw_b64', 'raw_sha256', 'raw_bytes',
                 'reported_exit_code', 'reported_close_confirmed'}, 'observation shape differs')
        _checked(row['slot_ms'] == (0, 1000, 5000)[i], 'observation slots not ordered')
        _integer(row['raw_bytes'], 'raw bytes', 0, MAX_TRANSPORT_BYTES)
        _checked(type(row['raw_b64']) is str and len(row['raw_b64']) <= 4*((MAX_TRANSPORT_BYTES+2)//3),
                 'raw base64 exceeds byte bound')
        try:
            raw = base64.b64decode(row['raw_b64'], validate=True)
        except (ValueError, binascii.Error):
            raise ExchangeStopped('invalid observation encoding') from None
        _checked(len(raw) == row['raw_bytes'] and _sha(raw) == row['raw_sha256'], 'observation digest differs')
        decoded.append(ObservationInput(row['slot_ms'], raw, row['reported_exit_code'], row['reported_close_confirmed']))
    return OperationInput(value['completion_known'], value['completion_evidence_ref'], tuple(decoded))


def _process(value, supplied):
    _checked(isinstance(value, Mapping), 'process evidence mapping required')
    value = plain_json(value)
    _checked(len(canonical_json_bytes(value)) <= MAX_PROCESS_BYTES, 'process evidence byte bound')
    reads = value.get('reads')
    _checked(type(reads) is list and len(reads) == len(supplied.observations), 'process/read envelope count differs')
    # The coordinator supplies real process measurements; these fields merely
    # retain and check their consistency. They do not measure processes here.
    for i, (row, observation) in enumerate(zip(reads, supplied.observations)):
        _checked(type(row) is dict, 'process row shape')
        _integer(row.get('read_ordinal'), 'read ordinal', 1, 600)
        _checked(row.get('slot_ms') == (0, 1000, 5000)[i], 'process slot differs')
        launch = _integer(row.get('launch_monotonic_ns'), 'process launch', 1)
        _integer(row.get('exit_monotonic_ns'), 'process exit', launch)
        _checked(type(row.get('returncode')) is int and row['returncode'] == observation.reported_exit_code,
                 'process return code differs')
        _checked(type(row.get('close_confirmed')) is bool
                 and row['close_confirmed'] == observation.reported_close_confirmed, 'process close differs')
        _checked(type(row.get('timeout_or_limit')) is bool, 'process timeout field missing')
        _checked(row.get('stdout_sha256') == _sha(observation.raw)
                 and row.get('stdout_bytes') == len(observation.raw), 'process stdout binding differs')
    return value


def _response(root, meta, ordinal, request):
    message = _message(root / 'responses' / str(ordinal).zfill(3), MAX_RESPONSE_BYTES)
    if message is None:
        return None
    value, digest = message
    _checked(set(value) == {'format', 'run_ref', 'ordinal', 'request_sha256',
             'operation_ref', 'log_watermark', 'context_sha256', 'input', 'reported_process_evidence'},
             'response shape differs')
    req, request_digest = request
    op = req['operation']
    _checked(value['format'] == FORMAT and value['run_ref'] == meta['run_ref']
             and value['ordinal'] == ordinal and value['request_sha256'] == request_digest
             and value['operation_ref'] == op['operation_ref']
             and value['log_watermark'] == op['log_watermark']
             and value['context_sha256'] == _sha(canonical_json_bytes(op['context'])),
             'response exact operation identity differs')
    decoded = _decode_input(value['input'])
    _process(value['reported_process_evidence'], decoded)
    return decoded, value, digest


def publish_response(root, ordinal, supplied, *, process_evidence):
    """Publish one externally acquired response. Existing/late responses refuse.

    Failed/nonzero/close-uncertain bytes may be retained and returned so that the
    controller/runner records the actual HOLD/stop. Raw native IDs are never
    rewritten or vouched for by this exchange.
    """
    root, meta, _ = _metadata(root)
    request = _request(root, meta, ordinal)
    _checked(request is not None, 'response has no complete request')
    req, request_digest = request
    supplied_mapping = _input_mapping(supplied)
    _decode_input(supplied_mapping)
    process = _process(process_evidence, supplied)
    used_reads, used_bytes = 0, 0
    read_ordinals = []
    for previous in range(1, ordinal):
        old_req = _request(root, meta, previous, allow_expired=True)
        _checked(old_req is not None, 'response history request missing')
        old = _response(root, meta, previous, old_req)
        _checked(old is not None, 'response history incomplete')
        used_reads += len(old[0].observations)
        used_bytes += sum(len(o.raw) for o in old[0].observations)
        read_ordinals.extend(r['read_ordinal'] for r in old[1]['reported_process_evidence']['reads'])
    read_ordinals.extend(r['read_ordinal'] for r in process['reads'])
    _checked(read_ordinals == list(range(1, len(read_ordinals)+1)), 'read ordinal continuity differs')
    _checked(used_reads + len(supplied.observations) <= meta['max_observations'], 'exchange read budget exceeded')
    _checked(used_bytes + sum(len(o.raw) for o in supplied.observations) <= meta['max_raw_bytes'],
             'exchange raw byte budget exceeded')
    op = req['operation']
    payload = {'format': FORMAT, 'run_ref': meta['run_ref'], 'ordinal': ordinal,
               'request_sha256': request_digest, 'operation_ref': op['operation_ref'],
               'log_watermark': op['log_watermark'], 'context_sha256': _sha(canonical_json_bytes(op['context'])),
               'input': supplied_mapping, 'reported_process_evidence': process}
    _request(root, meta, ordinal)  # Expiry/consumer stop checked again before publication.
    digest = _publish(root / 'responses' / str(ordinal).zfill(3), payload, MAX_RESPONSE_BYTES)
    return {'ordinal': ordinal, 'request_sha256': request_digest, 'response_sha256': digest,
            'reported_reads': len(supplied.observations), 'native_truth_verified': False}


class FileOperationPort:
    """Runner callback; writes/reads only local files and waits bounded time."""
    def __init__(self, root):
        self.root, self.metadata, self.metadata_digest = _metadata(root)
        self.ordinal = 0
        self._poisoned = False
        self._raw_bytes = 0
        self._observations = 0

    def __call__(self, operation):
        _checked(not self._poisoned, 'operation exchange is stopped')
        try:
            _checked(type(operation) is OperationRequest, 'typed OperationRequest required')
            _, meta, digest = _metadata(self.root)
            _checked(digest == self.metadata_digest, 'exchange metadata changed')
            ordinal = self.ordinal + 1
            _ordinal(meta, ordinal)
            now = time.monotonic_ns()
            request = {'format': FORMAT, 'run_ref': meta['run_ref'], 'ordinal': ordinal,
                       'metadata_sha256': digest, 'created_monotonic_ns': now,
                       'deadline_monotonic_ns': now + meta['timeout_ns'],
                       'operation': {'episode_ref': operation.episode_ref, 'kind': operation.kind,
                           'operation_ref': operation.operation_ref, 'attempt_ref': operation.attempt_ref,
                           'log_watermark': operation.log_watermark,
                           'controlled_value_digest': operation.controlled_value_digest,
                           'context': operation.context.to_mapping()}}
            self.ordinal = ordinal
            request_digest = _publish(self.root / 'requests' / str(ordinal).zfill(3), request, MAX_REQUEST_BYTES)
            parsed_request = _request(self.root, meta, ordinal)
            _checked(parsed_request[1] == request_digest, 'published request changed')
            while time.monotonic_ns() <= request['deadline_monotonic_ns']:
                response = _response(self.root, meta, ordinal, parsed_request)
                if response is not None:
                    _checked(time.monotonic_ns() <= request['deadline_monotonic_ns'],
                             'response arrived after operation deadline')
                    value, response_mapping, response_digest = response
                    ordinals = [r['read_ordinal'] for r in response_mapping['reported_process_evidence']['reads']]
                    _checked(ordinals == list(range(self._observations + 1,
                             self._observations + len(value.observations) + 1)),
                             'consumer read ordinal continuity differs')
                    self._raw_bytes += sum(len(o.raw) for o in value.observations)
                    self._observations += len(value.observations)
                    _checked(self._raw_bytes <= meta['max_raw_bytes']
                             and self._observations <= meta['max_observations'], 'consumer byte/read budget exceeded')
                    _atomic_file(self.root / 'receipts' / (str(ordinal).zfill(3)+'.received.json'), canonical_json_bytes({
                        'format': FORMAT, 'ordinal': ordinal, 'request_sha256': request_digest,
                        'response_sha256': response_digest, 'received_monotonic_ns': time.monotonic_ns(),
                        'meaning': 'EXCHANGE_BYTES_RECEIVED_NOT_CONTROLLER_ACK'}))
                    return value
                time.sleep(meta['poll_interval_ns'] / 1_000_000_000)
            _atomic_file(self.root / 'receipts' / (str(ordinal).zfill(3)+'.timeout.json'), canonical_json_bytes({
                'format': FORMAT, 'ordinal': ordinal, 'request_sha256': request_digest,
                'status': 'TIMED_OUT_NO_RETRY', 'observed_monotonic_ns': time.monotonic_ns()}))
            raise ExchangeStopped('operation response timeout; no retry')
        except Exception:
            self._poisoned = True
            raise
