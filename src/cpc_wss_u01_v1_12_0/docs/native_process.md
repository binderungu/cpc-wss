# Bounded fresh-process helper adapter — source 1.12.0

`NativeHelperProcess` is an explicit adapter for the external acquisition
coordinator. Import and construction perform no process/native access. A call
uses an externally frozen trusted command factory, operator/context and grant
gate. It is not a native authorization service or a verifier of supplied truth.

## API and scope

Existing arguments remain `stage_root`, `public_root`, `private_root`,
`operator_bases` with TASK/FOLLOWUP, `command_factory`, `gate`, `environment`,
optional `cleanup`, `timeout_ns` (maximum10seconds), and `poll_seconds`.
Additional explicit options:

- `command_kind='local'|'docker'`, default local. Set docker for a trusted wrapper
  whose underlying action is Docker-backed. Direct docker/docker-compose
  executable names are also detected, so omission cannot silently disable
  required cleanup for the ordinary CLI route.
- `public_command_factory(command_tuple, command_kind, container_name)` may
  return a bounded public-safe mapping supplied by the trusted integration.
  The default descriptor contains only a safe executable basename, argument
  count, kind and scoped container name. It never dumps actual argv.

Call `(operation_mapping, slot_ms, global_read_ordinal, completion_monotonic_ns)`.
The operation's exact source/actor/target/evidence bindings must agree with the
frozen operator base; controlled value digest is bound to that operation. The
ordinal must be next and at most18; slots are0/1000/5000. Scheduling and slot-order
policy also remain the coordinator's responsibility. Actual launch must fall
within its one-second slot lateness bound. Each actual helper uses a new process
and exclusive files/directories. A failed adapter never retries or resumes.

## Charged paths and terminal evidence

The adapter charges its launch attempt before writing intent/Popen. Validation
failures before this boundary do not imply a launched helper. The outer acquirer
may separately have charged its helper-call intent and must retain that
distinction. The following terminal fields explicitly separate stages:

```text
charged_launch_attempt = true
popen_attempted = false/true
process_started = false/true       # Popen returned a process handle
process_pid = integer or null
returncode = integer or null       # null on failed/unconfirmed start
terminal_status = COMPLETED or FAILED
failure_stage = stage code or null
failure_exception_type = exception class only, or null
termination_state = NOT_STARTED / EXITED / TERMINATED / KILLED / UNCONFIRMED
process_group_signal_attempted / process_group_signal_confirmed / process_group_signal_error_type
close_state = CONFIRMED / UNCONFIRMED / NOT_STARTED
close_confirmed = boolean
interrupted = boolean
timeout_or_limit = boolean
stdout_file_present / stdout_bytes / stdout_sha256 / stdout_facts_state
stderr_file_present / stderr_bytes / stderr_sha256 / stderr_facts_state
cleanup = normalized scope/attempt/absence/error/ref summary
```

Every charged operational failure path writes `read-NNN.process.json` and a
`read-NNN.failure.json`: Popen failure, post-charge gate stop, timing failure,
timeout, output bound, nonzero exit, parse/close failure and cleanup failure.
The failure receipt binds the process receipt digest and retained stdout facts.
An OSError from Popen is re-raised only after these receipts are persisted.
Gate/launch exceptions are likewise propagated after termination, applicable
cleanup and recording. Nonzero, timeout and parse/close-uncertain results retain
their actual raw bytes and false close flag for the acquirer's stop accounting.
Oversized output is retained and hashed incrementally before an explicit stop;
it is not loaded into the returned transport.

Raw output files are exclusive owner-only files. Failed Popen normally leaves
empty raw files with the exact empty-byte SHA256 and `process_started=false`.
If an earlier charged storage stage failed before file creation, ABSENT is
explicit and the empty digest does not claim a native observation. If hashing
itself is unavailable, facts are UNAVAILABLE with null hash/bytes/presence and
the error is propagated after recording; unknown is never converted into0.

No software can promise durable evidence when its evidence storage itself is
unwritable. Receipt-write/storage errors propagate and never become success;
the outer driver must retain its independent calling-process/exit/error receipt.
The claim above concerns the operational fault paths with writable evidence
storage, not power-loss or hostile-filesystem guarantees.

## Scoped Docker cleanup

Docker-backed commands require `cleanup(name)` before launch. A direct Docker
command must be `run`, use `--rm`, and have exactly one `--name` (or `--name=`)
equal to the adapter-generated `cpc-wss-worked-v1-read-NNN` scope. Foreign or
ambiguous names refuse before charge/Popen. Trusted wrappers declared docker
must preserve that same name at their underlying container boundary.

Every failed/interrupted/uncertain Docker attempt calls the cleanup callback,
including a Popen failure with unknown container state. The callback must return
a bounded public-safe mapping containing the exact `container_name` and
`confirmed_absent=True`. False, missing, foreign-name, malformed or raised cleanup
results are retained, leave absence unconfirmed and stop the workflow. Details
are written to `read-NNN.cleanup.json`; a normalized summary enters the terminal
process receipt. Only exception classes are copied into public failures.

SIGTERM/SIGKILL of a local Docker CLI does not establish container absence or
database close. **Forced cleanup and confirmed absence never count as read-close
confirmation.** A close flag requires exit0, coherent parsed helper receipt,
consistent snapshot and no READ_CLOSE_UNCONFIRMED, with no interruption/failure.
No later native operation/help may proceed from cleanup success alone.

If a process group exits between polling and signalling, or group signalling is
refused, the adapter records the unconfirmed group signal and its exception class.
It reaps or terminates only its known local child as a fallback. That local-child
terminal state does not confirm group closure; Docker scope absence still requires
the separate cleanup result. The failed/interrupted read never becomes close
confirmed through this fallback.

## Command privacy and delivery

Public intent contains `command_public_description` and
`actual_argv_private_only=True`; it contains no full `command`/argv array.
The exact argv is retained in owner-only
`private_root/read-NNN.command.private.json`; stderr is also private. **Do not
include these private files in reader/public packages.** A trusted public-command
or cleanup callback must return only approved public-safe metadata; it is not an
automatic sanitizer for an untrusted caller. The external freeze/manifest can
bind a safe command-policy/image/script identity without exposing secrets.

The process adapter measures local process timings and hashes bytes it retains.
It does not certify a successful form submit, correct Moodle current identity,
authorized rights/window/profile, source truth, controller ACK, scientific
usefulness, UF5 success, release or JLA readiness. The outer grant gate and
native acquisition/controller checks remain separate.

## Offline qualification

The repair qualification uses synthetic local Python subprocesses only. Docker
CLI cases are mocked, or a Python subprocess is tagged docker to exercise a
synthetic cleanup declaration. Such callbacks are not actual container absence
observations. Preserved tests cover all operational fault paths, empty/oversized
hashes, scoped cleanup absence/failure, no-retry and public command-argument
privacy. No Moodle, DB, Docker helper or worked demo is accessed by this QA.
