# Local operation exchange — source 1.12.0

`native_exchange.py` supplies a bounded filesystem exchange for the existing
`worked_runner.run_offline` operation port. It performs only local file reads,
writes and bounded waiting. It neither opens Moodle/DB/HTTP nor launches helpers,
generates source observations, signs authority, or releases controller barriers.
The existing runner's cooperative offline guard remains unchanged.

This is the exchange seam only. A separately authorized coordinator must perform
actual source acquisition outside the guarded runner process. Its integration,
native current facts, grants, process measurements and scientific validity are
separate responsibilities. The exchange does not assert that such a coordinator
already exists or has passed native qualification.

## API and lifecycle

Create an unused channel before starting the guarded workflow:

```python
from wss_bridge.native_exchange import (
    create_exchange, FileOperationPort, read_request, publish_response,
)

create_exchange(unused_channel_root, run_ref,
                max_operations=6, max_observations=18,
                max_raw_bytes=64 * 1024 * 1024,
                timeout_seconds=60, poll_interval=.01)
operation_port = FileOperationPort(unused_channel_root)
```

`operation_port(OperationRequest) -> OperationInput` is the child runner callback.
The runner has already durably created the exact operation before calling it.
The callback publishes its request, then waits for the corresponding response.
No request IDs, watermark, actor/context/source/target fields are patched to fit
previously acquired receipts. Install this callback in `RunnerPorts.operation`;
other explicit help, outcome signing and admission ports remain separate.

The external coordinator can poll:

```python
message = read_request(channel_root, ordinal)  # None until complete READY
# Check current owner grant/context/window, prospective action charge and
# request.deadline_monotonic_ns before every actual action. Acquire actual bytes
# only for message['operation']; retain raw/process evidence before parsing.
receipt = publish_response(channel_root, ordinal, typed_operation_input,
                           process_evidence=reported_process_evidence)
```

`ordinal` starts at 1 and is bounded by `max_operations`. Each request and response
uses one exclusive numbered directory; there is no overwrite, writable reopen,
retry, reset or resume. An attempted second `FileOperationPort` starting ordinal1
cannot overwrite the original request. All errors must stop the dependent native
action/workflow; retain channel files and the outer caller's failure/exit receipt.

`read_request` returns a JSON mapping with:

- `format`, `run_ref`, `ordinal`, `metadata_sha256`;
- `created_monotonic_ns`, `deadline_monotonic_ns` on the same POSIX host;
- `operation`: exact episode_ref, kind, operation_ref, attempt_ref, log_watermark,
  controlled_value_digest and complete controller context mapping;
- `request_sha256` identifying the canonical request payload bytes.

The mapping itself is an ordinary returned copy. The canonical file bytes/hash
are the retained identity; the server re-reads them when publishing a response.
`read_request` refuses expired or consumer-timed-out requests. Historical files
remain available for forensic inspection, but this action API does not silently
re-authorize them after expiry.

## Process evidence contract

`process_evidence` is an explicitly supplied JSON mapping, at most128KiB, with
`reads` containing exactly one record for each supplied `ObservationInput`.
Required fields per record:

```text
read_ordinal: globally contiguous integer 1..N across this channel
slot_ms: 0, then 1000, then 5000 within one operation
launch_monotonic_ns: positive integer
exit_monotonic_ns: integer >= launch
returncode: exact integer equal to ObservationInput.reported_exit_code
close_confirmed: boolean equal to ObservationInput.reported_close_confirmed
timeout_or_limit: boolean
stdout_sha256: sha256:<64 hex>, computed from exact ObservationInput.raw
stdout_bytes: integer equal to len(raw)
```

Other bounded JSON process/context/retention fields may accompany these records.
Use integers for measured nanoseconds/milliseconds. Canonical project JSON rejects
floats; the exchange API converts its seconds arguments to stored integer
`timeout_ns` and `poll_interval_ns`. Do not include credentials/private sessions
in exchange summaries that will be shared.

These are **reported process measurements**. The module checks consistency and
bindings; it does not measure or attest the subprocess itself. The external
coordinator must retain actual command/process/close/freshness/timing receipts,
enforce slot scheduling and lateness/timeout policy, gate/charge each actual
helper-launch attempt, and reconcile failed launches/envelopes. A launched helper
with zero/malformed stdout must remain an attempted read; an empty bytes
ObservationInput can retain that failure with its actual nonzero/close status.
An unknown submit result may return `completion_known=False`, an exact completion
evidence reference and zero observations/reads. It is not permission to submit
again or progress to help/follow-up.

The module permits malformed native raw bytes or supplied nonzero/uncertain-close
results to cross the exchange intact. The runner retains every returned raw input
and the controller/native transport checks determine its HOLD/stop. The exchange
never manufactures a native MATCH, rewrites receipt source IDs, or certifies that
validly encoded source claims are truthful. Completion_known is also an externally
supplied declaration whose real native basis belongs in the coordinator receipts.

## Retention, limits and barriers

The channel contains `exchange.json`, `requests/NNN/{payload,READY}.json`,
`responses/NNN/{payload,READY}.json` and `receipts/NNN.received.json` or a timeout
receipt. Payload files are fsynced and atomically renamed from exclusive staging
files before READY is published. Incomplete staging directories are retained and
ignored as incomplete; they are never repaired or overwritten. READY binds the
canonical payload digest and byte length. Requests are at most128KiB; observations
retain each raw blob's length/digest/base64 with the inherited8MiB transport limit,
at most3 observations/operation, channel read budget and maximum64MiB total raw
bytes. Response process evidence is separately bounded128KiB.

Root/ancestor/message symlinks, FIFO/nonregular and multiply-linked file leaves
are refused using existing ledger file guards. Exact response identity binds
run/ordinal/request digest/operation/watermark/context digest. Both publisher and
consumer enforce byte/read budgets; global read ordinals are continuous. Deadlines
are bounded and a timed-out/poisoned consumer cannot retry a later operation.

`NNN.received.json` means **EXCHANGE_BYTES_RECEIVED_NOT_CONTROLLER_ACK**. Only the
runner/controller's subsequent retained capture and actual positive ACK can
release help or the next operation. The external coordinator must not infer an
ACK from READY, received bytes, a process exit0, HTTP200 or a native helper MATCH.

Storage is cooperative single-writer POSIX storage on one host. Hash/READY and
fsync identify locally retained bytes and completed writes; they do not prove
source truth, hostile-peer safety, distributed custody, crash/power-loss behavior,
rights, owner authority, scientific usefulness, public release or JLA readiness.

## Qualification scope

The separate campaign qualification suite exercises synthetic request/response
roundtrips, including separate Python processes with the child offline guard,
WAIT/MATCH byte preservation, exact identity, limits, path/tamper refusal, late
responses, incomplete readiness, unknown completion and no-retry behavior. It
does not access a native source, execute the worked demo, or make new scientific
observations. Existing source1.11.0 and its historical QA remain unchanged.
