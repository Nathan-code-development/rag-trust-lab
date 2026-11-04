"""Auditors: prompts, user-visible outputs, and persisted derived artifacts."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .canary import CanaryRegistry
from .echo_llm import PromptRecord


@dataclass
class Finding:
    oracle: str            # prompt | output | artifact | key
    actor: Optional[str]
    location: str
    foreign_owners: List[str]
    tokens: List[str]
    detail: str = ""

    def to_json(self):
        return self.__dict__


def audit_prompts(log: Sequence[PromptRecord], reg: CanaryRegistry) -> List[Finding]:
    """Each prompt may contain only the triggering actor's canaries.

    Prompts with no actor (background jobs) must not mix canaries of >1 owner.
    """
    out = []
    for i, r in enumerate(log):
        found = reg.find(r.prompt)
        owners = sorted({c.owner for c in found})
        if r.actor is not None:
            bad = [c for c in found if c.owner != str(r.actor)]
            if bad:
                out.append(Finding("prompt", r.actor, f"prompt[{i}] {r.route or ''}",
                                   sorted({c.owner for c in bad}), sorted({c.token for c in bad})))
        elif len(owners) > 1:
            out.append(Finding("prompt", None, f"prompt[{i}] {r.route or ''} (no actor)", owners,
                               sorted({c.token for c in found}), "background prompt mixes tenants"))
    return out


def audit_output(actor: str, location: str, payload, reg: CanaryRegistry) -> List[Finding]:
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    bad = reg.foreign(text, actor)
    if not bad:
        return []
    return [Finding("output", actor, location, sorted({c.owner for c in bad}), sorted({c.token for c in bad}))]


def scan_artifacts(root: str | Path, reg: CanaryRegistry, owner_key_re: str = r"u(\d+)_",
                   max_bytes: int = 20_000_000) -> List[Finding]:
    """Walk persisted derived state (cache dirs, vector stores, sqlite files).

    Two oracles:
    * key oracle  — an artifact whose *name/key* encodes an owner (``u{id}_``)
      must contain only that owner's canaries;
    * mix oracle  — any single artifact containing canaries of >1 owner.
    Files whose key has no owner but contain any canary are reported as
    ``unscoped`` (the shipped ``bm25_N_v1.pkl`` pattern).
    """
    out: List[Finding] = []
    rx = re.compile(owner_key_re)
    for p in Path(root).rglob("*"):
        if not p.is_file() or p.stat().st_size > max_bytes:
            continue
        blobs: List[tuple] = []
        if p.suffix in (".sqlite3", ".sqlite", ".db"):
            try:
                con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
                for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                    cols = [c[1] for c in con.execute(f"PRAGMA table_info('{t}')")]
                    for row in con.execute(f"SELECT * FROM '{t}'"):
                        key = " ".join(str(v) for v, c in zip(row, cols) if "name" in c or "id" in c)
                        blobs.append((f"{p.name}:{t}:{key[:80]}", key, " ".join(str(v) for v in row)))
                con.close()
            except sqlite3.Error:
                pass
        else:
            data = p.read_bytes().decode("latin-1", errors="ignore")
            blobs.append((str(p.relative_to(root)), p.name, data))
        for loc, key, data in blobs:
            found = reg.find(data)
            if not found:
                continue
            owners = sorted({c.owner for c in found})
            m = rx.search(key)
            if m and any(o != m.group(1) for o in owners):
                out.append(Finding("key", m.group(1), loc, [o for o in owners if o != m.group(1)],
                                   sorted({c.token for c in found}), "artifact keyed to one owner holds another's data"))
            elif len(owners) > 1:
                out.append(Finding("artifact", None, loc, owners, sorted({c.token for c in found}),
                                   "artifact mixes tenants"))
            elif not m:
                out.append(Finding("artifact", None, loc, owners, sorted({c.token for c in found}),
                                   "unscoped artifact (key has no owner)"))
    return out
