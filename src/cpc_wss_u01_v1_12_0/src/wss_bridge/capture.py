"""Explicit same-process consume capture for WP05; not a secure observer."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import time
import uuid
from typing import Callable

from .ledger import SnapshotReference, SnapshotStore
from .primitives import ContractError, canonical_json_bytes, require_identifier, require_int, require_rfc3339
from .renderer import CatalogSnapshot, Generation, RenderResult, ResolutionBinding, render


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def new_ref(prefix: str) -> str:
    return prefix + ":" + uuid.uuid4().hex


def instant(text: str) -> datetime:
    require_rfc3339(text, "clock.utc")
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


@dataclass(frozen=True, slots=True)
class ClockObservation:
    utc: str
    sequence: int
    monotonic_ns: int
    clock_id: str
    source: str

    def __post_init__(self) -> None:
        instant(self.utc)
        require_int(self.sequence, "clock.sequence")
        require_int(self.monotonic_ns, "clock.monotonic_ns")
        require_identifier(self.clock_id, "clock.clock_id")
        if self.source not in ("REAL_UTC", "SYNTHETIC_FAULT_INJECTION"):
            raise ContractError("clock.source: unsupported")

    def to_mapping(self) -> dict:
        return {name: getattr(self, name) for name in self.__slots__}


class LocalClock:
    """Actual UTC/monotonic readings, no delay or corrected/future time.

    Injection requires an explicit fault label. A reading sequence counts local
    observations, not distributed order, and cannot override UTC inequalities.
    """
    def __init__(self, clock_id: str, *, fault_reader: Callable | None = None) -> None:
        self.clock_id = require_identifier(clock_id, "clock_id")
        self.source = "REAL_UTC" if fault_reader is None else "SYNTHETIC_FAULT_INJECTION"
        self._reader, self._last, self._sequence = fault_reader, None, 0
        self.observations: list[ClockObservation] = []

    def observe(self) -> ClockObservation:
        if self._reader is None:
            utc = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            mono = time.monotonic_ns()
        else:
            utc, mono = self._reader()
        obs = ClockObservation(utc, self._sequence, mono, self.clock_id, self.source)
        self.observations.append(obs)  # retain valid-shaped even backwards readings
        if self._last is not None and (instant(obs.utc) < instant(self._last.utc)
                                      or obs.monotonic_ns < self._last.monotonic_ns):
            raise ContractError("clock: backwards observation; no repair")
        self._last, self._sequence = obs, self._sequence + 1
        return obs


def save(store: SnapshotStore, prefix: str, raw: bytes) -> SnapshotReference:
    """Exclusive immutable name and durability/readback; never overwrite/retry."""
    ref = store.put(new_ref(prefix), raw)
    if store.get(ref) != raw:
        raise ContractError("capture: persisted bytes differ")
    return ref


@dataclass(frozen=True, slots=True)
class Consumption:
    result: RenderResult
    observation: ClockObservation
    prompt_reference: SnapshotReference
    generation_reference: SnapshotReference
    prompt_use_reference: SnapshotReference
    generation_use_reference: SnapshotReference
    manifest_reference: SnapshotReference


def capture_and_render(prompt_raw: bytes, generation_raw: bytes,
                       catalog: CatalogSnapshot, binding: ResolutionBinding,
                       store: SnapshotStore, invocation_ref: str,
                       clock: LocalClock) -> Consumption:
    """Save raw/partial inputs, normalize once, capture and consume same objects.

    Any exception leaves all completed/partial files intact. Caller must have
    allocated invocation_ref before entering and must retain the failure. Capture
    names are local sidecar identities; no path/raw contents enter signed CPC.
    """
    require_identifier(invocation_ref, "invocation_ref")
    prompt_ref = save(store, "actual-prompt", prompt_raw)
    generation_transport = save(store, "raw-generation-transport", generation_raw)
    generation = Generation.from_bytes(generation_raw)
    generation_ref = save(store, "actual-generation", generation.canonical_bytes)
    catalog_ref = save(store, "catalog-snapshot", catalog.raw_bytes)
    # Same immutable objects are passed directly. No file reread supplies a
    # replacement prompt/generation to the renderer after the capture point.
    result = render(prompt_raw, generation, catalog, binding)
    if result.prompt_bytes is not prompt_raw or result.generation is not generation:
        raise ContractError("capture: consume object identity differs")
    observed = clock.observe()  # actual consume completion, before proof signing
    uses = []
    for component, ref in (("prompt", prompt_ref), ("generation", generation_ref)):
        uses.append(save(store, "use-" + component, canonical_json_bytes({
            "format": "wss-consume-use-v1", "invocation_ref": invocation_ref,
            "component_id": component, "capture_reference": ref.to_mapping(),
            "observed_use": observed.to_mapping(), "body_digest": sha(result.body),
            "same_process_same_instance": True, "independent_secure_observer": False,
        })))
    manifest = save(store, "consume-manifest", canonical_json_bytes({
        "format": "wss-consumption-v1", "invocation_ref": invocation_ref,
        "prompt_reference": prompt_ref.to_mapping(),
        "generation_transport_reference": generation_transport.to_mapping(),
        "generation_reference": generation_ref.to_mapping(),
        "catalog_reference": catalog_ref.to_mapping(),
        "prompt_use_reference": uses[0].to_mapping(),
        "generation_use_reference": uses[1].to_mapping(),
        "render_trace": result.trace, "observed_use": observed.to_mapping(),
    }))
    return Consumption(result, observed, prompt_ref, generation_ref, uses[0], uses[1], manifest)
