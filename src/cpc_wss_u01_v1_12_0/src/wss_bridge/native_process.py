"""Explicit bounded fresh-process helper adapter for the external coordinator.

No import/construction launches a process or accesses a database. A frozen trusted
command factory supplies the pinned helper/container invocation when called.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import re
import stat
import subprocess
import time

from .native_transport import NativeReadTransport, MAX_TRANSPORT_BYTES
from .primitives import canonical_json_bytes, plain_json
from .native_acquisition import AcquisitionStopped
from .ledger import _real_directory, _fsync_directory


def _directory_new(path):
    path = _real_directory(path, exists=False)
    path.mkdir(mode=0o700)
    _fsync_directory(path.parent)
    return path


def _write_new(path, raw):
    _real_directory(Path(path).parent, exists=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise AcquisitionStopped('HELPER_REGULAR_EXCLUSIVE_FILE_REQUIRED')
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    parent = os.open(Path(path).parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _facts(path):
    """Hash retained bytes incrementally, including oversized failure output."""
    if not path.exists():
        return {'present': False, 'bytes': 0, 'sha256': 'sha256:'+hashlib.sha256(b'').hexdigest()}
    _real_directory(path.parent, exists=True)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AcquisitionStopped('HELPER_RAW_REGULAR_FILE_REQUIRED')
        h, size = hashlib.sha256(), 0
        while True:
            raw = os.read(fd, 1024*1024)
            if not raw:
                break
            h.update(raw);size += len(raw)
        return {'present': True, 'bytes': size, 'sha256': 'sha256:'+h.hexdigest()}
    finally:
        os.close(fd)


def _is_docker(command):
    return Path(command[0]).name.lower() in {'docker', 'docker-compose', 'docker-compose.exe', 'docker.exe'}


def _public_command(command, kind, name, factory):
    """Default carries no argv; an explicit public factory is a trusted boundary."""
    if factory is not None:
        supplied = plain_json(factory(tuple(command), kind, name))
        if type(supplied) is not dict or len(canonical_json_bytes(supplied)) > 16384:
            raise AcquisitionStopped('BOUNDED_TRUSTED_PUBLIC_COMMAND_DESCRIPTION_REQUIRED')
        return supplied
    base = Path(command[0]).name
    if re.fullmatch(r'[A-Za-z0-9._+-]{1,128}', base) is None:
        base = 'REDACTED_EXECUTABLE_NAME'
    return {'executable_basename': base, 'argument_count': len(command)-1,
            'command_kind': kind, 'scoped_container_name': name if kind == 'docker' else None,
            'argv_disclosed': False, 'source': 'TRUSTED_IN_MEMORY_COMMAND_FACTORY'}


class NativeHelperProcess:
    def __init__(self, *, stage_root, public_root, private_root, operator_bases,
                 command_factory, gate, environment, cleanup=None,
                 timeout_ns=10000000000, poll_seconds=.005,
                 command_kind='local', public_command_factory=None):
        if set(operator_bases) != {'TASK', 'FOLLOWUP'}:
            raise AcquisitionStopped('TWO_FROZEN_OPERATOR_BASES_REQUIRED')
        if type(timeout_ns) is not int or not 0 < timeout_ns <= 10000000000:
            raise AcquisitionStopped('HELPER_TIMEOUT_BOUND')
        if type(poll_seconds) not in (float, int) or not 0 < poll_seconds <= .05:
            raise AcquisitionStopped('HELPER_POLL_BOUND')
        if command_kind not in ('local', 'docker'):
            raise AcquisitionStopped('HELPER_COMMAND_KIND_REQUIRED')
        if (not callable(command_factory) or not callable(gate)
                or (cleanup is not None and not callable(cleanup))
                or (public_command_factory is not None and not callable(public_command_factory))):
            raise AcquisitionStopped('TRUSTED_HELPER_CALLBACKS_REQUIRED')
        if command_kind == 'docker' and cleanup is None:
            raise AcquisitionStopped('DOCKER_SCOPED_CLEANUP_REQUIRED')
        self.stage = _directory_new(stage_root)
        self.public = _directory_new(public_root)
        self.private = _directory_new(private_root)
        self.operator_bases = copy.deepcopy(operator_bases)
        self.command_factory, self.gate = command_factory, gate
        self.environment, self.cleanup = dict(environment), cleanup
        self.command_kind, self.public_command_factory = command_kind, public_command_factory
        self.timeout_ns, self.poll_seconds = timeout_ns, poll_seconds
        self.reads, self.failed = 0, False

    def __call__(self, op, slot, ordinal, completion_ns):
        if self.failed:
            raise AcquisitionStopped('NO_RETRY_HELPER_PROCESS')
        try:
            return self._call(op, slot, ordinal, completion_ns)
        except BaseException:
            self.failed = True
            raise

    def _call(self, op, slot, ordinal, completion_ns):
        self.gate()
        if (type(ordinal) is not int or ordinal != self.reads + 1 or ordinal > 18
                or type(slot) is not int or slot not in (0, 1000, 5000)
                or type(completion_ns) is not int):
            raise AcquisitionStopped('HELPER_READ_ORDINAL_OR_BUDGET')
        kind = op['kind']
        operator = copy.deepcopy(self.operator_bases[kind])
        context = op['context']
        target = context['task_target' if kind == 'TASK' else 'followup_target']
        if (operator['source'] != context['source'] or operator['actor'] != context['actor']
                or any(operator['target'].get(k) != v for k, v in target.items()
                       if k != 'controlled_value_digest')):
            raise AcquisitionStopped('FROZEN_HELPER_CONTEXT_CONFLICT')
        operator['target']['controlled_value_digest'] = op['controlled_value_digest']
        for name in ('clean_interval_evidence_ref', 'prior_operations_evidence_ref', 'sole_writer_evidence_ref'):
            if operator.get(name) != context.get(name):
                raise AcquisitionStopped('FROZEN_HELPER_EVIDENCE_CONFLICT')
        operator['native_result_known'] = True
        for key, prefix in [('read_context_ref', 'read-context'), ('transaction_ref', 'transaction'),
                            ('connection_ref', 'connection'), ('target_window_before_ref', 'window-before'),
                            ('target_window_after_ref', 'window-after')]:
            operator[key] = prefix + ':worked:' + str(ordinal)
        stem = 'read-' + str(ordinal).zfill(3)
        request = {'observation_ref': 'observation:worked:' + str(ordinal),
                   'operation_ref': op['operation_ref'], 'observer_sequence': ordinal,
                   'log_watermark': op['log_watermark']}
        operator_path, request_path = self.stage/(stem+'.operator.json'), self.stage/(stem+'.request.json')
        _write_new(operator_path, canonical_json_bytes(operator))
        _write_new(request_path, canonical_json_bytes(request))
        rawpath, errpath = self.public/(stem+'.stdout.bin'), self.private/(stem+'.stderr.raw')
        name = 'cpc-wss-worked-v1-read-' + str(ordinal).zfill(3)
        command = self.command_factory(kind, operator_path, request_path, name)
        if (type(command) is not list or not command
                or any(type(x) is not str or not x or '\x00' in x for x in command)):
            raise AcquisitionStopped('TRUSTED_HELPER_COMMAND_REQUIRED')
        command_kind = 'docker' if _is_docker(command) else self.command_kind
        if command_kind == 'docker' and self.cleanup is None:
            raise AcquisitionStopped('DOCKER_SCOPED_CLEANUP_REQUIRED')
        if _is_docker(command):
            names = []
            for index, token in enumerate(command):
                if token == '--name':
                    names.append(command[index+1] if index+1 < len(command) else None)
                elif token.startswith('--name='):
                    names.append(token.split('=', 1)[1])
            if names != [name] or 'run' not in command or '--rm' not in command:
                raise AcquisitionStopped('EXACT_NAMED_DISPOSABLE_DOCKER_HELPER_REQUIRED')
        public_command = _public_command(command, command_kind, name, self.public_command_factory)
        self.gate()
        target_ns = completion_ns + slot * 1000000
        launch = time.monotonic_ns()
        if not 0 <= launch - target_ns <= 1000000000:
            raise AcquisitionStopped('HELPER_ACTUAL_LAUNCH_TIMING')
        self.reads += 1  # charge before intent/Popen, including every failure below
        charged_at = launch
        p, interrupted, timeout_or_limit, close = None, False, False, False
        popen_attempted, process_started = False, False
        group_signal_attempted, group_signal_confirmed, group_signal_error_type = False, None, None
        termination, stage, failure_stage = 'NOT_STARTED', 'INTENT_RETENTION', None
        error, cleanup_error, parse_error_type = None, None, None
        cleanup_summary = {'required': False, 'attempted': False, 'container_name': name,
                           'confirmed_absent': None, 'error_type': None, 'receipt_ref': None}
        stdout, stderr = None, None
        try:
            # Real argv can contain a secret even when the trusted factory was
            # configured incorrectly. Never serialize it into public intent.
            _write_new(self.private/(stem+'.command.private.json'), canonical_json_bytes({'command': command}))
            _write_new(self.public/(stem+'.intent.json'), canonical_json_bytes({
                'read_ordinal': ordinal, 'operation_ref': op['operation_ref'], 'slot_ms': slot,
                'charged_launch_attempt': True, 'launch_intent_monotonic_ns': charged_at,
                'command_public_description': public_command, 'actual_argv_private_only': True,
                'operator_sha256': 'sha256:'+hashlib.sha256(operator_path.read_bytes()).hexdigest(),
                'request_sha256': 'sha256:'+hashlib.sha256(request_path.read_bytes()).hexdigest()}))
            stage = 'OUTPUT_FILE_CREATION'
            for path in (rawpath, errpath):
                _write_new(path, b'')
            stdout, stderr = rawpath.open('ab'), errpath.open('ab')
            stage = 'PRE_LAUNCH_GATE'
            self.gate()
            launch = time.monotonic_ns()
            if not 0 <= launch - target_ns <= 1000000000:
                raise AcquisitionStopped('HELPER_ACTUAL_LAUNCH_TIMING')
            stage = 'POPEN'
            popen_attempted = True
            p = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                 env=self.environment, start_new_session=True)
            process_started, termination = True, 'UNCONFIRMED'
            stage = 'ACTIVE_PROCESS_GATE'
            while p.poll() is None:
                self.gate()
                now = time.monotonic_ns()
                if now-launch > self.timeout_ns:
                    failure_stage, interrupted, timeout_or_limit = 'TIMEOUT', True, True
                    break
                if rawpath.stat().st_size > MAX_TRANSPORT_BYTES or errpath.stat().st_size > 1048576:
                    failure_stage, interrupted, timeout_or_limit = 'OUTPUT_LIMIT', True, True
                    break
                time.sleep(self.poll_seconds)
        except BaseException as exc:
            error, failure_stage = exc, failure_stage or stage
            interrupted = process_started
        finally:
            if p is not None:
                if p.poll() is None:
                    interrupted = True
                    try:
                        group_signal_attempted = True
                        os.killpg(p.pid, signal.SIGTERM)
                        group_signal_confirmed = True
                        termination = 'TERMINATED'
                        try:
                            p.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            os.killpg(p.pid, signal.SIGKILL)
                            termination = 'KILLED'
                            p.wait(timeout=1)
                    except BaseException as exc:
                        group_signal_confirmed = False
                        group_signal_error_type = type(exc).__name__
                        if isinstance(exc, ProcessLookupError) and p.poll() is not None:
                            termination = 'EXITED'
                        else:
                            # A short-lived child may exit between poll and the
                            # group signal, or a local sandbox may refuse group
                            # signalling. Reap/terminate only this known child;
                            # record that the group signal was NOT confirmed.
                            try:
                                try:
                                    p.wait(timeout=.05)
                                    termination = 'EXITED'
                                except subprocess.TimeoutExpired:
                                    p.terminate();termination = 'TERMINATED'
                                    try:p.wait(timeout=1)
                                    except subprocess.TimeoutExpired:
                                        p.kill();termination = 'KILLED';p.wait(timeout=1)
                            except BaseException as termination_error:
                                termination = 'UNCONFIRMED'
                                error = error or AcquisitionStopped('HELPER_PROCESS_TERMINATION_UNCONFIRMED')
                                failure_stage = failure_stage or 'PROCESS_TERMINATION'
                else:
                    termination = 'EXITED'
            for stream in (stdout, stderr):
                if stream is not None:
                    try:
                        stream.flush();os.fsync(stream.fileno());stream.close()
                    except BaseException as exc:
                        error, failure_stage = error or exc, failure_stage or 'RAW_RETENTION'
            end = time.monotonic_ns()
            code = p.returncode if p is not None else None
            if process_started and end-launch > self.timeout_ns:
                timeout_or_limit, interrupted = True, True
                failure_stage = failure_stage or 'TIMEOUT'
            def retained_facts(path):
                nonlocal error, failure_stage
                try:
                    facts = _facts(path)
                    return {**facts, 'state': 'AVAILABLE' if facts['present'] else 'ABSENT'}
                except BaseException as exc:
                    error, failure_stage = error or exc, failure_stage or 'RAW_FACTS_UNAVAILABLE'
                    return {'present': None, 'bytes': None, 'sha256': None, 'state': 'UNAVAILABLE'}
            raw_facts, err_facts = retained_facts(rawpath), retained_facts(errpath)
            if ((raw_facts['bytes'] is not None and raw_facts['bytes'] > MAX_TRANSPORT_BYTES)
                    or (err_facts['bytes'] is not None and err_facts['bytes'] > 1048576)):
                timeout_or_limit, failure_stage = True, failure_stage or 'OUTPUT_LIMIT'
            if error is None and not failure_stage and code == 0:
                stage = 'PARSE_OR_CLOSE_VALIDATION'
                try:
                    receipt = NativeReadTransport.from_json(rawpath.read_bytes()).receipt
                    close = (receipt.consistent_snapshot_observed
                             and 'READ_CLOSE_UNCONFIRMED' not in receipt.diagnostics
                             and receipt.status.value in ('MATCH_OBSERVED', 'NO_MATCH'))
                    if not close:
                        failure_stage = 'CLOSE_UNCONFIRMED'
                except BaseException as exc:
                    failure_stage = 'PARSE_OR_CLOSE_VALIDATION'
                    # The bounded exception class is retained; no raw exception
                    # string, argv, stdout or private stderr enters this receipt.
                    error = exc if not isinstance(exc, Exception) else None
                    parse_error_type = type(exc).__name__
            elif error is None and not failure_stage and code != 0:
                failure_stage = 'NONZERO_EXIT'
            close = bool(close and not interrupted and not failure_stage and error is None)
            cleanup_summary['required'] = bool(command_kind == 'docker' and not close)
            # Local synthetic processes can also provide a cleanup callback. For
            # Docker every interrupted/failed/uncertain attempt requires one.
            if (cleanup_summary['required'] or (interrupted and self.cleanup is not None)):
                cleanup_summary['attempted'] = True
                cleanup_summary['receipt_ref'] = stem+'.cleanup.json'
                try:
                    supplied = plain_json(self.cleanup(name))
                    if type(supplied) is not dict or len(canonical_json_bytes(supplied)) > 65536:
                        raise AcquisitionStopped('BOUNDED_CLEANUP_RECEIPT_REQUIRED')
                    matched = supplied.get('container_name') == name
                    confirmed = matched and supplied.get('confirmed_absent') is True
                    cleanup_summary['confirmed_absent'] = bool(confirmed)
                    # Preserve the trusted cleanup's detailed receipt separately;
                    # this callback must return a public-safe bounded mapping.
                    _write_new(self.public/(stem+'.cleanup.json'), canonical_json_bytes({
                        'requested_container_name': name, 'scope_name_matches': matched,
                        'confirmed_absent': bool(confirmed), 'reported': supplied,
                        'forced_cleanup_is_not_close_confirmation': True}))
                    if cleanup_summary['required'] and not confirmed:
                        cleanup_error = AcquisitionStopped('HELPER_CONTAINER_ABSENCE_UNCONFIRMED')
                except BaseException as exc:
                    cleanup_error = exc
                    cleanup_summary['confirmed_absent'] = None
                    cleanup_summary['error_type'] = type(exc).__name__
                    # If the detailed receipt has not been published, preserve a
                    # normalized exception-only cleanup receipt before process.
                    if not (self.public/(stem+'.cleanup.json')).exists():
                        _write_new(self.public/(stem+'.cleanup.json'), canonical_json_bytes({
                            'requested_container_name': name, 'confirmed_absent': None,
                            'error_type': type(exc).__name__,
                            'forced_cleanup_is_not_close_confirmation': True}))
                if cleanup_error is not None:
                    failure_stage = 'CLEANUP_UNCONFIRMED'
                    close = False
            failed = bool(error is not None or failure_stage or not close or cleanup_error is not None)
            proc = {'read_ordinal': ordinal, 'operation_ref': op['operation_ref'], 'slot_ms': slot,
                    'charged_launch_attempt': True, 'charged_monotonic_ns': charged_at,
                    'popen_attempted': popen_attempted, 'process_started': process_started,
                    'process_pid': p.pid if p is not None else None,
                    'launch_monotonic_ns': launch, 'exit_monotonic_ns': end,
                    'launch_lateness_ns': launch-target_ns, 'returncode': code,
                    'terminal_status': 'FAILED' if failed else 'COMPLETED',
                    'failure_stage': failure_stage,
                    'failure_exception_type': type(error).__name__ if error is not None else parse_error_type,
                    'termination_state': termination,
                    'process_group_signal_attempted': group_signal_attempted,
                    'process_group_signal_confirmed': group_signal_confirmed,
                    'process_group_signal_error_type': group_signal_error_type,
                    'close_state': 'CONFIRMED' if close else 'UNCONFIRMED' if process_started else 'NOT_STARTED',
                    'close_confirmed': close, 'timeout_or_limit': timeout_or_limit,
                    'interrupted': interrupted,
                    'stdout_sha256': raw_facts['sha256'], 'stdout_bytes': raw_facts['bytes'],
                    'stdout_file_present': raw_facts['present'],
                    'stdout_facts_state': raw_facts['state'],
                    'stderr_sha256': err_facts['sha256'], 'stderr_bytes': err_facts['bytes'],
                    'stderr_file_present': err_facts['present'], 'stderr_private_only': True,
                    'stderr_facts_state': err_facts['state'],
                    'command_kind': command_kind, 'actual_argv_private_only': True,
                    'cleanup': cleanup_summary,
                    'forced_cleanup_is_not_close_confirmation': cleanup_summary['attempted']}
            _write_new(self.public/(stem+'.process.json'), canonical_json_bytes(proc))
            if failed:
                self.failed = True
                _write_new(self.public/(stem+'.failure.json'), canonical_json_bytes({
                    'read_ordinal': ordinal, 'operation_ref': op['operation_ref'],
                    'failure_stage': failure_stage, 'failure_exception_type': proc['failure_exception_type'],
                    'process_receipt_sha256': 'sha256:'+hashlib.sha256(canonical_json_bytes(proc)).hexdigest(),
                    'stdout_sha256': raw_facts['sha256'], 'stdout_bytes': raw_facts['bytes'],
                    'no_retry': True, 'close_confirmed': False,
                    'cleanup_confirmed_absent': cleanup_summary['confirmed_absent']}))
        if error is not None:
            raise error
        if cleanup_error is not None:
            raise AcquisitionStopped('HELPER_SCOPED_CLEANUP_FAILED_NO_RETRY') from None
        if failure_stage == 'OUTPUT_LIMIT':
            raise AcquisitionStopped('HELPER_RAW_OUTPUT_BOUND_RETAINED')
        return {'raw': rawpath.read_bytes(), 'process': proc}
