"""Prospective typed producer snapshot index; explicit local IO only.

The index is outside snapshot payloads. It never reconstructs reference IDs from
filenames, payload shapes or old stores. Cooperative POSIX integrity, not WORM,
independent custody, native truth, approval or a publication boundary.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
from pathlib import Path
import os

from .ledger import (AppendOnlyLedger, LedgerScope, SnapshotStore, SnapshotReference,
    LedgerError, _real_directory, _new_file, _read_file, _checked_fd, _fsync_directory)
from .native_contract import LedgerRecord, RecordKind
from .primitives import ContractError, canonical_json_bytes, decode_json_object, require_identifier
from .capture import new_ref

FORMAT='wss-producer-reference-index-v1'
PURPOSE='PRODUCER_SNAPSHOT_REFERENCES'
MAX_REFERENCES=10000
MAX_TOTAL_BYTES=64*1024*1024


class ReferenceIndexError(ContractError):
    """Operational reference-index refusal, never a CPC/native verdict."""


class ProducerReferenceIndex:
    def __init__(self,root,store,call_ref,invocation_ref,journal,*,writable):
        self.root,self.store,self.call_ref,self.invocation_ref=root,store,call_ref,invocation_ref
        self.journal,self._writable,self._poisoned=journal,writable,False
        self._metadata=canonical_json_bytes({'format':FORMAT,'store_ref':store._store_ref,
            'call_ref':call_ref,'invocation_ref':invocation_ref,'ledger_scope':journal.scope.to_mapping()})

    @classmethod
    def create(cls,root,store,*,call_ref,invocation_ref):
        if type(store) is not IndexedSnapshotStore or store._reference_index is not None:
            raise ReferenceIndexError('new unbound indexed store required')
        require_identifier(call_ref,'call_ref');require_identifier(invocation_ref,'invocation_ref')
        store._check_metadata()
        if {p.name for p in store._directory.iterdir()}!={'snapshot-store.meta.json'}:
            raise ReferenceIndexError('cannot backfill existing snapshot store')
        target=_real_directory(root,exists=False)
        if target.parent!=store._directory.parent or target.name!='reference-index':
            raise ReferenceIndexError('index must be sibling of producer snapshots')
        target.mkdir(mode=0o700,exist_ok=False)
        scope=LedgerScope(new_ref('producer-reference-ledger'),call_ref,PURPOSE)
        journal=AppendOnlyLedger.create(target/'journal',scope)
        handle=cls(target,store,call_ref,invocation_ref,journal,writable=True)
        _new_file(target/'index.meta.json',handle._metadata)
        _new_file(target/'.index.lock',b'')
        _fsync_directory(target);_fsync_directory(target.parent)
        store._reference_index=handle
        return handle

    @classmethod
    def open_readonly(cls,producer_root,*,invocation_ref,call_ref):
        require_identifier(invocation_ref,'invocation_ref')
        require_identifier(call_ref,'call_ref')
        parent=_real_directory(producer_root,exists=True)
        root=_real_directory(parent/'reference-index',exists=True)
        meta=decode_json_object(_read_file(root/'index.meta.json',1048576))
        if (set(meta)!={'format','store_ref','call_ref','invocation_ref','ledger_scope'} or meta['format']!=FORMAT
                or meta['invocation_ref']!=invocation_ref or meta['call_ref']!=call_ref):
            raise ReferenceIndexError('reference index owner/scope mismatch')
        require_identifier(meta['call_ref'],'call_ref');require_identifier(meta['store_ref'],'store_ref')
        scope=LedgerScope(**meta['ledger_scope'])
        if scope.run_ref!=meta['call_ref'] or scope.purpose!=PURPOSE or scope.source_epoch_ref is not None:
            raise ReferenceIndexError('reference journal scope mismatch')
        store=SnapshotStore.open_existing(parent/'snapshots',meta['store_ref'])
        handle=cls(root,store,meta['call_ref'],invocation_ref,AppendOnlyLedger.open_existing(root/'journal',scope),writable=False)
        handle.references()
        return handle

    def _check_metadata(self):
        _real_directory(self.root,exists=True)
        self.store._check_metadata()
        if _read_file(self.root/'index.meta.json',1048576)!=self._metadata:
            raise ReferenceIndexError('reference metadata changed')

    @contextmanager
    def _guard(self,write=False):
        if write and (not self._writable or self._poisoned):
            raise ReferenceIndexError('reference index stopped or readonly')
        fd=None
        try:
            self._check_metadata()
            fd=_checked_fd(self.root/'.index.lock',os.O_RDONLY)
            fcntl.flock(fd,fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            self._check_metadata()
            if write and (not self._writable or self._poisoned):
                raise ReferenceIndexError('reference index stopped while waiting')
            yield
        except Exception:
            if write:self._poisoned=True
            raise
        finally:
            if fd is not None:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

    def _references(self,*,verify_bytes):
        refs,seen,total=[],set(),0
        for record in self.journal.read_records():
            row=record.payload
            if (record.kind is not RecordKind.AUDIT_REFERENCE or set(row)!={'audit_ref','status','format','call_ref','invocation_ref','reference'}
                    or row['audit_ref']!=record.record_ref or row['status']!='RECORDED'
                    or row['format']!=FORMAT or row['call_ref']!=self.call_ref or row['invocation_ref']!=self.invocation_ref):
                raise ReferenceIndexError('reference record shape/owner mismatch')
            reference=SnapshotReference.from_mapping(row['reference'])
            if reference.store_ref!=self.store._store_ref or reference.snapshot_ref in seen:
                raise ReferenceIndexError('foreign or duplicate snapshot reference')
            seen.add(reference.snapshot_ref);total+=reference.byte_length
            if len(refs)>=MAX_REFERENCES or total>MAX_TOTAL_BYTES:
                raise ReferenceIndexError('reference index capacity exceeded')
            if verify_bytes:self.store.get(reference)
            refs.append(reference)
        return tuple(refs)

    def references(self):
        with self._guard():return self._references(verify_bytes=True)

    def _record(self,reference):
        """Only the prospective store.put path calls this; no public backfill API."""
        with self._guard(write=True):
            refs=self._references(verify_bytes=False)
            if (type(reference) is not SnapshotReference or reference.store_ref!=self.store._store_ref
                    or any(r.snapshot_ref==reference.snapshot_ref for r in refs)):
                raise ReferenceIndexError('reference scope/uniqueness failure')
            if len(refs)>=MAX_REFERENCES or sum(r.byte_length for r in refs)+reference.byte_length>MAX_TOTAL_BYTES:
                raise ReferenceIndexError('reference index capacity exceeded')
            self.store.get(reference) # byte readback before the caller receives ref
            token=new_ref('producer-reference')
            self.journal.append(LedgerRecord(token,RecordKind.AUDIT_REFERENCE,token,
                {'audit_ref':token,'status':'RECORDED','format':FORMAT,'call_ref':self.call_ref,
                 'invocation_ref':self.invocation_ref,'reference':reference.to_mapping()}))
            after=self._references(verify_bytes=False)
            if not after or after[-1]!=reference:raise ReferenceIndexError('reference journal readback differs')


class IndexedSnapshotStore(SnapshotStore):
    """Original snapshot encoding/storage plus prospective reference recording."""
    def __init__(self,directory,store_ref):
        super().__init__(directory,store_ref)
        self._reference_index=None

    def put(self,snapshot_ref,content):
        index=self._reference_index
        if index is None or not index._writable or index._poisoned:
            raise ReferenceIndexError('snapshot reference recording unavailable')
        reference=super().put(snapshot_ref,content)
        index._record(reference)
        return reference
