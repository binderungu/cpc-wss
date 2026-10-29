"""Explicit parent-side ordinary submit/read coordination, never called on import.

The offline runner stays in a separate process. Actual HTTP/helper adapters and
current human authority are supplied explicitly; this class cannot create them.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import time

from .native_transport import NativeReadTransport
from .primitives import ContractError
from .worked_runner import ObservationInput, OperationInput


class AcquisitionStopped(ContractError):
    pass


class BoundedNativeAcquirer:
    """One-use ordered six-operation parent coordinator; no retry or reopen.

    ``helper_read`` must retain raw bytes before interpretation and return a
    mapping with ``raw`` bytes and an actual ``process`` receipt. ``record`` must
    durably persist every event before returning. Adapters are trusted operator
    code; supplied declarations are not independent native/human attestation.
    """

    def __init__(self, *, client, helper_read, gate, record, episodes, task_value,
                 followup_value, grant, now_ns=time.monotonic_ns, sleep=time.sleep,
                 utc_now=lambda: datetime.now(timezone.utc), pre_submit_gate=None):
        if (type(task_value) is not bytes or type(followup_value) is not bytes
                or len(episodes) != 3 or len(set(episodes)) != 3):
            raise AcquisitionStopped('EXACT_THREE_EPISODE_INPUTS_REQUIRED')
        if (grant.get('native_execution_authorized') is not True
                or grant.get('max_TASK_finalizations') != 3
                or grant.get('max_FOLLOWUP_finalizations') != 3
                or grant.get('max_protocol_helper_calls') != 18
                or grant.get('max_publication_attempts') != 4
                or not grant.get('owner_authorization_ref')
                or not grant.get('sole_writer_ref')):
            raise AcquisitionStopped('SCOPED_CURRENT_GRANT_REQUIRED')
        try:
            expiry = datetime.fromisoformat(grant['expires_UTC'])
        except (KeyError, ValueError, TypeError):
            raise AcquisitionStopped('GRANT_EXPIRY_REQUIRED')
        if expiry.tzinfo is None:
            raise AcquisitionStopped('GRANT_TIMEZONE_REQUIRED')
        self.expiry = expiry
        self.client, self.helper_read = client, helper_read
        self.gate, self.record = gate, record
        self.values = {'TASK': task_value, 'FOLLOWUP': followup_value}
        self.order = tuple((e, k) for e in episodes for k in ('TASK', 'FOLLOWUP'))
        self.ordinal = 0
        self.submits = {'TASK': 0, 'FOLLOWUP': 0}
        self.reads = 0
        self.failed = False
        self.now_ns, self.sleep, self.utc_now = now_ns, sleep, utc_now
        self.pre_submit_gate = pre_submit_gate

    def _gate(self):
        if self.failed or self.utc_now() >= self.expiry:
            raise AcquisitionStopped('STOPPED_OR_GRANT_EXPIRED')
        self.gate()

    def acquire(self, request):
        if self.failed:
            raise AcquisitionStopped('NO_RETRY_STOPPED_ACQUISITION')
        try:
            return self._acquire(request)
        except Exception:
            self.failed = True
            raise

    def _acquire(self, request):
        self._gate()
        op = request['operation']
        if (self.ordinal >= len(self.order)
                or (op['episode_ref'], op['kind']) != self.order[self.ordinal]):
            raise AcquisitionStopped('OPERATION_ORDER_OR_BUDGET')
        kind = op['kind']
        expected = 'sha256:' + hashlib.sha256(self.values[kind]).hexdigest()
        if op['controlled_value_digest'] != expected:
            raise AcquisitionStopped('CONTROLLED_VALUE_CONFLICT')
        context = op['context']
        if context['actor']['expected_userid'] != 4:
            raise AcquisitionStopped('WORKED_ACTOR_SCOPE')
        self.record('PROSPECTIVE_NATIVE_OPERATION', {
            'ordinal': self.ordinal + 1, 'request_sha256': request['request_sha256'],
            'operation_ref': op['operation_ref'], 'kind': kind,
            'watermark': op['log_watermark']})
        prepared = self.client.get_target(kind)
        self._gate()
        if self.pre_submit_gate is not None:
            self.pre_submit_gate(op)
            self._gate()
        if self.submits[kind] >= 3:
            raise AcquisitionStopped('SUBMIT_BUDGET')
        self.submits[kind] += 1
        self.record('SUBMIT_INTENT_DURABLE', {
            'operation_ref': op['operation_ref'], 'kind': kind,
            'kind_attempt_ordinal': self.submits[kind]})
        try:
            completion = self.client.submit(prepared, self.values[kind])
        except Exception:
            self.record('SUBMIT_UNRESOLVED', {
                'operation_ref': op['operation_ref'], 'no_retry': True})
            raise AcquisitionStopped('NATIVE_RESULT_UNRESOLVED_NO_RETRY')
        self.record('ORDINARY_NATIVE_RETURN', {
            **completion, 'operation_ref': op['operation_ref'], 'kind': kind})
        completion_ref = 'completion:' + op['operation_ref']
        if not completion['known']:
            self.failed = True
            return OperationInput(False, completion_ref, ()), {'reads': [], 'completion': completion}
        t0 = completion['return_monotonic_ns']
        observations, processes = [], []
        for slot in (0, 1000, 5000):
            self._gate()
            target = t0 + slot * 1000000
            if self.now_ns() < target:
                self.sleep((target - self.now_ns()) / 1000000000)
            self._gate()
            if not 0 <= self.now_ns() - target <= 1000000000:
                raise AcquisitionStopped('PROTOCOL_LAUNCH_TIMING_INCOMPLETE')
            if self.reads >= 18:
                raise AcquisitionStopped('HELPER_READ_BUDGET')
            self.reads += 1
            self.record('READ_INTENT_DURABLE', {
                'operation_ref': op['operation_ref'], 'slot_ms': slot,
                'read_ordinal': self.reads})
            got = self.helper_read(op, slot, self.reads, t0)
            raw, proc = got['raw'], got['process']
            self.record('READ_PROCESS_RETURN', proc)
            if (type(raw) is not bytes or proc['read_ordinal'] != self.reads
                    or proc['slot_ms'] != slot
                    or proc['stdout_sha256'] != 'sha256:' + hashlib.sha256(raw).hexdigest()
                    or proc['stdout_bytes'] != len(raw)
                    or not target <= proc['launch_monotonic_ns'] <= target + 1000000000
                    or proc['exit_monotonic_ns'] < proc['launch_monotonic_ns']):
                raise AcquisitionStopped('ACTUAL_PROCESS_RECEIPT_CONFLICT')
            clean = (proc['returncode'] == 0 and proc['close_confirmed'] is True
                     and proc['timeout_or_limit'] is False
                     and proc['exit_monotonic_ns'] - proc['launch_monotonic_ns'] <= 10000000000)
            observations.append(ObservationInput(slot, raw, proc['returncode'], clean))
            processes.append(proc)
            if not clean:
                self.failed = True
                break
            receipt = NativeReadTransport.from_json(raw).receipt
            if (not receipt.consistent_snapshot_observed
                    or 'READ_CLOSE_UNCONFIRMED' in receipt.diagnostics
                    or receipt.operation_ref != op['operation_ref']
                    or receipt.log_watermark != op['log_watermark']):
                raise AcquisitionStopped('SOURCE_PROCESS_OR_IDENTITY_CONFLICT')
            expected_target = dict(context['task_target' if kind == 'TASK' else 'followup_target'])
            expected_target['controlled_value_digest'] = op['controlled_value_digest']
            coherent_context = (receipt.source is not None and receipt.actor is not None
                and receipt.target is not None
                and receipt.source.to_mapping() == context['source']
                and receipt.actor.to_mapping() == context['actor']
                and receipt.target.to_mapping() == expected_target
                and all(getattr(receipt, field) == context.get(field) for field in
                    ('clean_interval_evidence_ref', 'prior_operations_evidence_ref', 'sole_writer_evidence_ref')))
            if not coherent_context:
                # Return the retained raw observation for the child's original
                # binding/HOLD accounting, but never poll or submit again.
                self.failed = True
                break
            if receipt.status.value != 'NO_MATCH':
                break
            # Only a coherent WAIT observation permits another scheduled read.
            wait_issues = {'NO_MATCH', 'NATIVE_OCCURRENCE_UNAVAILABLE',
                           'SOURCE_SNAPSHOT_UNAVAILABLE', 'CAPTURE_STATUS_NOT_MATCH'}
            if set(receipt.binding_issues()) - wait_issues:
                raise AcquisitionStopped('NO_MATCH_BINDING_CONFLICT')
        self.ordinal += 1
        return OperationInput(True, completion_ref, tuple(observations)), {
            'reads': processes, 'completion': completion,
            'actual_submit_attempts': dict(self.submits),
            'actual_protocol_read_attempts': self.reads,
            'controller_ACK_not_inferred_here': True}
