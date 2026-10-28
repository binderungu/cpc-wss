"""Structural operator declarations and explicit byte-only reference checking.

No configuration, approval reference, successful parse or reference byte match
establishes authority, native verification, operational readiness or scientific
sufficiency. Importing this module does not read files or import pinned code.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
from types import MappingProxyType
from typing import Any, Mapping

from .primitives import (
    ContractError,
    decode_json_object,
    require_digest,
    require_identifier,
    require_int,
    require_mapping,
    require_rfc3339,
    require_text,
)


CONFIGURATION_VERSION = "wss-operator-declaration-1.0"
PINNED_REFERENCE_MANIFEST_DIGEST = (
    "sha256:9c4dee342dc86a4c614a337f6891bdae63e8fd75b00f2267e3081de011bc62ad"
)
FACT_NAMES = (
    "runtime_profile", "key_registry", "key_policy", "role_policy",
    "runtime_dependency", "source_epoch", "actor_registry", "context_map",
    "approved_content", "outcome_recipe", "sandbox_authorization",
    "internal_material_rights", "execution_grant",
)


@dataclass(frozen=True)
class DeclarationRef:
    """An opaque external reference, never the object or key material itself."""

    ref: str = field(repr=False)
    sha256: str | None = None

    def __post_init__(self) -> None:
        require_identifier(self.ref, "declaration_ref.ref")
        if self.sha256 is not None:
            require_digest(self.sha256, "declaration_ref.sha256")

    @classmethod
    def from_mapping(cls, value: Any) -> DeclarationRef:
        row = require_mapping(value, "declaration_ref", required=("ref",), optional=("sha256",))
        return cls(row["ref"], row.get("sha256"))

    def to_dict(self) -> dict[str, Any]:
        return {"ref": self.ref, "sha256": self.sha256}


@dataclass(frozen=True)
class FactDeclaration:
    """PENDING is unknown; DECLARED means supplied and structurally valid only."""

    state: str = "PENDING"
    reference: DeclarationRef | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.state not in ("PENDING", "DECLARED"):
            raise ContractError("fact.state: unsupported declaration state")
        if self.state == "PENDING" and self.reference is not None:
            raise ContractError("fact.reference: pending fact must have no reference")
        if self.state == "DECLARED" and not isinstance(self.reference, DeclarationRef):
            raise ContractError("fact.reference: declared fact requires a reference")

    @classmethod
    def from_mapping(cls, value: Any) -> FactDeclaration:
        row = require_mapping(value, "fact", required=("state", "reference"))
        reference = row["reference"]
        return cls(row["state"], None if reference is None else DeclarationRef.from_mapping(reference))

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state, "reference": None if self.reference is None else self.reference.to_dict()}


@dataclass(frozen=True)
class OperatorConfiguration:
    """Closed offline declaration schema; no profile/key/content object accepted.

    The five required operator bindings fail closed when missing or malformed.
    Missing optional facts remain explicitly pending. There is deliberately no
    authorized/ready property and no method that launches a dependent action.
    """

    configuration_ref: str
    scope_grant_ref: DeclarationRef = field(repr=False)
    operator_ref: str = field(repr=False)
    reference_manifest_digest: str
    evidence_root_ref: str = field(repr=False)
    facts: Mapping[str, FactDeclaration] = field(default_factory=dict, repr=False)
    validation_time: str | None = None
    configuration_version: str = CONFIGURATION_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.configuration_ref, "configuration.configuration_ref")
        require_identifier(self.operator_ref, "configuration.operator_ref")
        require_identifier(self.evidence_root_ref, "configuration.evidence_root_ref")
        if not isinstance(self.scope_grant_ref, DeclarationRef):
            raise ContractError("configuration.scope_grant_ref: declaration reference required")
        require_digest(self.reference_manifest_digest, "configuration.reference_manifest_digest")
        if self.reference_manifest_digest != PINNED_REFERENCE_MANIFEST_DIGEST:
            raise ContractError("configuration.reference_manifest_digest: unsupported reference binding")
        if self.configuration_version != CONFIGURATION_VERSION:
            raise ContractError("configuration.configuration_version: unsupported version")
        if self.validation_time is not None:
            require_rfc3339(self.validation_time, "configuration.validation_time")
        raw_facts = require_mapping(self.facts, "configuration.facts", optional=FACT_NAMES)
        normalized = {}
        for name in FACT_NAMES:
            declaration = raw_facts.get(name, FactDeclaration())
            if not isinstance(declaration, FactDeclaration):
                raise ContractError("configuration.facts: FactDeclaration required")
            normalized[name] = declaration
        object.__setattr__(self, "facts", MappingProxyType(normalized))

    @classmethod
    def from_mapping(cls, value: Any) -> OperatorConfiguration:
        row = require_mapping(
            value,
            "configuration",
            required=("configuration_version", "configuration_ref", "scope_grant_ref", "operator_ref",
                      "reference_manifest_digest", "evidence_root_ref"),
            optional=("facts", "validation_time"),
        )
        facts = require_mapping(row.get("facts", {}), "configuration.facts", optional=FACT_NAMES)
        return cls(
            configuration_ref=row["configuration_ref"],
            scope_grant_ref=DeclarationRef.from_mapping(row["scope_grant_ref"]),
            operator_ref=row["operator_ref"],
            reference_manifest_digest=row["reference_manifest_digest"],
            evidence_root_ref=row["evidence_root_ref"],
            facts={name: FactDeclaration.from_mapping(declaration) for name, declaration in facts.items()},
            validation_time=row.get("validation_time"),
            configuration_version=row["configuration_version"],
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> OperatorConfiguration:
        return cls.from_mapping(decode_json_object(raw, "configuration"))

    @property
    def pending_facts(self) -> tuple[str, ...]:
        """Report unknown declarations; an empty tuple is not a readiness claim."""
        pending = tuple(name for name in FACT_NAMES if self.facts[name].state == "PENDING")
        return pending + (("validation_time",) if self.validation_time is None else ())

    def to_dict(self) -> dict[str, Any]:
        """Explicit reference-only serialization; it does not resolve any target."""
        return {
            "configuration_version": self.configuration_version,
            "configuration_ref": self.configuration_ref,
            "scope_grant_ref": self.scope_grant_ref.to_dict(),
            "operator_ref": self.operator_ref,
            "reference_manifest_digest": self.reference_manifest_digest,
            "evidence_root_ref": self.evidence_root_ref,
            "facts": {name: self.facts[name].to_dict() for name in FACT_NAMES},
            "validation_time": self.validation_time,
        }


def parse_operator_configuration(raw: str | bytes) -> OperatorConfiguration:
    """Parse supplied JSON only; no filesystem access or authority evaluation."""
    return OperatorConfiguration.from_json(raw)


@dataclass(frozen=True)
class ReferenceByteReceipt:
    """A byte-integrity result, not a dependency/runtime qualification result."""

    manifest_sha256: str
    matched_files: tuple[str, ...]
    evidence_class: str = field(default="SOURCE_BYTE_MATCH_ONLY", init=False)

    def __post_init__(self) -> None:
        require_digest(self.manifest_sha256, "reference_receipt.manifest_sha256")
        if not isinstance(self.matched_files, tuple) or any(type(path) is not str for path in self.matched_files):
            raise ContractError("reference_receipt.matched_files: string tuple required")


def _relative_reference_path(value: Any) -> str:
    text = require_text(value, "reference.path", max_chars=1024)
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or "\\" in text or path.as_posix() != text:
        raise ContractError("reference.path: normalized relative path required")
    if not path.parts or text == ".":
        raise ContractError("reference.path: file path required")
    return text


def _read_reference_bytes(
    path: Path, *, byte_limit: int, expected_size: int | None = None,
    retain_bytes: bool = False,
) -> tuple[str, bytes | None]:
    """Bounded explicit file IO; source copies are hashed without buffering."""
    if path.is_symlink():
        raise ContractError("references: symlinks are unsupported")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError("references: ordinary source file required")
        if metadata.st_size > byte_limit or (expected_size is not None and metadata.st_size != expected_size):
            raise ContractError("references: source size mismatch")
        digest = hashlib.sha256()
        chunks = [] if retain_bytes else None
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, byte_limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > byte_limit:
                raise ContractError("references: source exceeds byte limit")
            digest.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        if expected_size is not None and total != expected_size:
            raise ContractError("references: source size mismatch")
        return "sha256:" + digest.hexdigest(), None if chunks is None else b"".join(chunks)
    finally:
        os.close(descriptor)


def verify_pinned_references(references_root: str | Path) -> ReferenceByteReceipt:
    """Explicit read-only byte check of the pinned tree, without executing code.

    Reads the manifest and listed files, rejects symlinks and unexpected files,
    and checks exact bytes/sizes. The generated manifest digest is embedded in
    this source so editing a manifest alongside changed copies cannot suffice.
    No module import, schema evaluation, profile validation or native call occurs.
    """
    try:
        root = Path(references_root)
        if root.is_symlink() or not root.is_dir():
            raise ContractError("references: ordinary directory required")
        manifest_path = root / "REFERENCE_MANIFEST.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ContractError("references: ordinary manifest file required")
        digest, raw_manifest = _read_reference_bytes(
            manifest_path, byte_limit=1024 * 1024, retain_bytes=True,
        )
        if digest != PINNED_REFERENCE_MANIFEST_DIGEST:
            raise ContractError("references: pinned manifest byte mismatch")
        manifest = require_mapping(
            decode_json_object(raw_manifest, "reference_manifest"), "reference_manifest",
            required=("manifest_version", "reference_class", "cpc_implementation_version", "cpc_contract_version",
                      "cpc_schema_version", "comparator_version", "project_code_executed", "files"),
        )
        expected_metadata = {
            "manifest_version": "wss-reference-manifest-1.0", "reference_class": "BYTE_EXACT_SOURCE_PIN_ONLY",
            "cpc_implementation_version": "2.0.2", "cpc_contract_version": "2.0.1",
            "cpc_schema_version": "cpc-2.0.1", "comparator_version": "1.0.1",
        }
        if any(manifest[name] != value for name, value in expected_metadata.items()) or manifest["project_code_executed"] is not False:
            raise ContractError("references: unsupported manifest metadata")
        entries = manifest["files"]
        if not isinstance(entries, list) or not entries:
            raise ContractError("references: nonempty file inventory required")
        expected_files = {"REFERENCE_MANIFEST.json"}
        for entry in entries:
            row = require_mapping(entry, "reference_entry", required=("path", "source_path", "size_bytes", "source_sha256", "copied_sha256"))
            relative = _relative_reference_path(row["path"])
            _relative_reference_path(row["source_path"])
            if relative in expected_files:
                raise ContractError("references: duplicate file inventory")
            expected_files.add(relative)
            require_int(row["size_bytes"], "reference_entry.size_bytes", minimum=0)
            require_digest(row["source_sha256"], "reference_entry.source_sha256")
            require_digest(row["copied_sha256"], "reference_entry.copied_sha256")
            if row["source_sha256"] != row["copied_sha256"]:
                raise ContractError("references: source/copy digest disagreement")
        actual_files = set()
        for path in root.rglob("*"):
            if path.is_symlink():
                raise ContractError("references: symlinks are unsupported")
            if path.is_file():
                actual_files.add(path.relative_to(root).as_posix())
            elif not path.is_dir():
                raise ContractError("references: unsupported filesystem entry")
        if actual_files != expected_files:
            raise ContractError("references: exact file inventory mismatch")
        for entry in entries:
            source_digest, _ = _read_reference_bytes(
                root / entry["path"], byte_limit=entry["size_bytes"],
                expected_size=entry["size_bytes"],
            )
            if source_digest != entry["copied_sha256"]:
                raise ContractError("references: pinned source byte mismatch")
        return ReferenceByteReceipt(digest, tuple(sorted(expected_files - {"REFERENCE_MANIFEST.json"})))
    except (OSError, UnicodeError):
        raise ContractError("references: source bytes unavailable") from None
