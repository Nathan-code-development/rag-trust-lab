"""Benchmark & corpus loaders.

Supported sources
-----------------
1. **Course benchmark** (Sprint 1, 80 questions) — ``eval_dataset_en.csv`` +
   the frozen index. Column names are mapped through a small YAML/dict so the
   loader does not have to guess the Sprint 1 schema.
2. **Production vector store** — ``local_vectors.sqlite3`` (post-isolation
   backend) or a Chroma directory (pre-isolation backend, needs ``chromadb``).
3. **Plain text / PDF directory** — chunked with the frozen 200/80 chunker.
4. **SQuAD 2.0** — public replication of the central claim: SQuAD 2.0's
   unanswerable questions were written *adversarially on-topic* (same
   paragraph, plausible answer), i.e. exactly our ``on_topic_unanswerable``
   class; off-topic questions are produced by scoping a question to a
   different article.
"""

from __future__ import annotations

import csv
import json
import random
import re
import sqlite3
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..corpus import Corpus, chunk_text_words
from ..types import (ANSWERABLE, OFF_TOPIC, ON_TOPIC_UNANSWERABLE, Chunk, Question,
                     read_jsonl, write_jsonl)

# ------------------------------------------------------------ course CSV

DEFAULT_COURSE_COLUMNS = {
    "qid": ["qid", "id", "question_id"],
    "question": ["question", "question_en", "query"],
    "material_id": ["material_id", "material"],
    "gold_chunk_ids": ["expected_chunk_ids", "gold_chunk_ids", "expected_chunks", "relevant_chunk_ids"],
    "gold_document": ["expected_document", "gold_document"],
    "gold_pages": ["expected_pages", "expected_page", "gold_pages"],
    "split": ["split"],
    "qtype": ["type", "question_type", "category", "qtype"],
    "qclass": ["class", "qclass", "answerability"],
    "gold_answer": ["expected_answer", "answer", "gold_answer"],
}


def _pick(row: Dict[str, str], names: List[str]) -> Optional[str]:
    for n in names:
        if n in row and str(row[n]).strip() != "":
            return str(row[n]).strip()
    return None


def _split_ids(v: Optional[str]) -> List[str]:
    if not v:
        return []
    return [x.strip() for x in re.split(r"[;|,\s]+", v) if x.strip()]


def load_course_csv(path: str | Path, owner_id: str = "0", columns: Dict[str, List[str]] = None,
                    corpus: Optional[Corpus] = None) -> List[Question]:
    """Load the Sprint 1 benchmark.

    Class rule (Sprint 1 ``sufficiency.calibrate``): answerable iff
    ``expected_document`` is non-empty. Off-topic vs on-topic unanswerable is
    taken from a ``class``/``type`` column if present (values containing
    'off' / 'on'), otherwise left as ``on_topic_unanswerable`` and flagged in
    ``meta['class_inferred']`` — fix it by hand in that case.

    If gold chunk ids are missing but document (+pages) are given and a
    ``corpus`` is passed, gold = chunks of that document (on those pages).
    """
    cols = dict(DEFAULT_COURSE_COLUMNS)
    cols.update(columns or {})
    out: List[Question] = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for i, row in enumerate(csv.DictReader(f)):
            qid = _pick(row, cols["qid"]) or f"Q{i + 1:03d}"
            doc = _pick(row, cols["gold_document"])
            gold = _split_ids(_pick(row, cols["gold_chunk_ids"]))
            raw_cls = (_pick(row, cols["qclass"]) or _pick(row, cols["qtype"]) or "").lower()
            meta = {"raw": row}
            if doc or gold:
                qclass = ANSWERABLE
            elif "off" in raw_cls:
                qclass = OFF_TOPIC
            elif "on" in raw_cls or "unans" in raw_cls:
                qclass = ON_TOPIC_UNANSWERABLE
            else:
                qclass = ON_TOPIC_UNANSWERABLE
                meta["class_inferred"] = True
            mid = _pick(row, cols["material_id"])
            if not gold and doc and corpus is not None and mid:
                pages = {int(p) for p in _split_ids(_pick(row, cols["gold_pages"])) if p.isdigit()}
                gold = [c.chunk_id for c in corpus.scope(owner_id, [mid])
                        if (c.document == doc) and (not pages or c.page in pages)]
                meta["gold_from_document"] = True
            out.append(Question(qid=qid, question=_pick(row, cols["question"]) or "", qclass=qclass,
                                material_id=mid, owner_id=owner_id, gold_chunk_ids=gold,
                                gold_document=doc, gold_answer=_pick(row, cols["gold_answer"]),
                                split=(_pick(row, cols["split"]) or "dev").lower(),
                                qtype=_pick(row, cols["qtype"]), meta=meta))
    return out


# ------------------------------------------------------ production stores

def corpus_from_local_sqlite(path: str | Path, default_owner: str = "0") -> Corpus:
    """Read the post-isolation backend's ``local_vectors.sqlite3``.

    Collections are named ``u{user}_material_{id}`` (new) or ``material_{id}``
    (legacy). Embeddings are ignored on purpose — research runs re-encode so
    that the encoder is an explicit experimental variable.
    """
    db = Path(path)
    if db.is_dir():
        db = db / "local_vectors.sqlite3"
    con = sqlite3.connect(str(db))
    chunks = []
    for name, item_id, doc, meta in con.execute(
            "SELECT collection_name, item_id, document, metadata FROM vectors"):
        md = json.loads(meta or "{}")
        m = re.match(r"^(?:u(\d+)_)?material_(.+)$", name)
        owner = str(md.get("user_id") or (m.group(1) if m and m.group(1) else default_owner))
        mid = str(md.get("material_id") or (m.group(2) if m else name))
        chunks.append(Chunk(chunk_id=str(item_id), text=doc, material_id=mid, owner_id=owner,
                            document=md.get("document"), page=md.get("page"),
                            chunk_index=int(md.get("chunk_index", 0) or 0),
                            meta={k: v for k, v in md.items()
                                  if k not in ("document", "page", "chunk_index", "user_id", "material_id")}))
    con.close()
    return Corpus(chunks)


def corpus_from_chroma(path: str | Path, default_owner: str = "0") -> Corpus:
    """Read a Chroma persistent dir (Sprint 1 ``chroma_data``). Needs ``chromadb``."""
    import chromadb
    client = chromadb.PersistentClient(path=str(path))
    chunks = []
    for c in client.list_collections():
        name = c if isinstance(c, str) else c.name
        m = re.match(r"^(?:u(\d+)_)?material_(.+)$", name)
        if not m:
            continue
        col = client.get_collection(name=name)
        data = col.get(include=["documents", "metadatas"])
        for cid, doc, md in zip(data["ids"], data["documents"], data["metadatas"]):
            md = md or {}
            chunks.append(Chunk(chunk_id=str(cid), text=doc, material_id=str(md.get("material_id", m.group(2))),
                                owner_id=str(md.get("user_id") or m.group(1) or default_owner),
                                document=md.get("document"), page=md.get("page"),
                                chunk_index=int(md.get("chunk_index", 0) or 0)))
    return Corpus(chunks)


def corpus_from_text_dir(path: str | Path, owner_id: str = "0", size: int = 200, overlap: int = 80) -> Corpus:
    """Each file = one material. ``.txt``/``.md`` directly; ``.pdf`` page-aware via pypdf."""
    chunks = []
    files = sorted(p for p in Path(path).iterdir() if p.suffix.lower() in (".txt", ".md", ".pdf"))
    for mi, p in enumerate(files, 1):
        pages: List[Tuple[Optional[int], str]]
        if p.suffix.lower() == ".pdf":
            from pypdf import PdfReader
            pages = [(i + 1, pg.extract_text() or "") for i, pg in enumerate(PdfReader(str(p)).pages)]
        else:
            pages = [(None, p.read_text(encoding="utf-8", errors="replace"))]
        idx = 0
        if pages and pages[0][0] is None:
            for t in chunk_text_words(pages[0][1], size=size, overlap=overlap):
                chunks.append(Chunk(f"{mi}_{idx}", t, str(mi), owner_id, p.name, None, idx))
                idx += 1
        else:
            # page-aware: chunk the concatenation, attribute each chunk to its first page
            words, page_of = [], []
            for pno, txt in pages:
                w = txt.split()
                words += w
                page_of += [pno] * len(w)
            step = size - overlap
            for start in range(0, len(words), step):
                t = " ".join(words[start:start + size])
                chunks.append(Chunk(f"{mi}_{idx}", t, str(mi), owner_id, p.name, page_of[start], idx,
                                    meta={"pages": sorted(set(page_of[start:start + size]))}))
                idx += 1
                if start + size >= len(words):
                    break
    return Corpus(chunks)


# ------------------------------------------------------------- SQuAD 2.0

def load_squad2(path: str | Path, n_articles: Optional[int] = None, seed: int = 13,
                off_topic_per_article: int = 2, max_q_per_article: Optional[int] = None
                ) -> Tuple[Corpus, List[Question]]:
    """SQuAD 2.0 dev JSON -> (corpus, questions).

    article = material; paragraph = chunk; owner = "0".
    * answerable: gold = the paragraph containing the answer
    * is_impossible: ``on_topic_unanswerable`` (adversarially written to look answerable)
    * ``off_topic``: an answerable question from article A, scoped to article B
    Split: articles are assigned dev/test 50/50 (by article, to avoid leakage).
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))["data"]
    rng = random.Random(seed)
    arts = list(data)
    rng.shuffle(arts)
    if n_articles:
        arts = arts[:n_articles]
    chunks, qs, pool_answerable = [], [], []
    for ai, art in enumerate(arts):
        mid = f"sq{ai}"
        split = "dev" if ai % 2 == 0 else "test"
        art_qs = []
        for pi, para in enumerate(art["paragraphs"]):
            cid = f"{mid}_p{pi}"
            chunks.append(Chunk(cid, para["context"], mid, "0", art["title"], None, pi))
            for qa in para["qas"]:
                if qa.get("is_impossible"):
                    art_qs.append(Question(qa["id"], qa["question"], ON_TOPIC_UNANSWERABLE, mid, "0",
                                           [], art["title"], None, split, "squad_impossible"))
                else:
                    q = Question(qa["id"], qa["question"], ANSWERABLE, mid, "0", [cid], art["title"],
                                 qa["answers"][0]["text"] if qa["answers"] else None, split, "squad")
                    art_qs.append(q)
                    pool_answerable.append(q)
        if max_q_per_article:
            rng.shuffle(art_qs)
            art_qs = art_qs[:max_q_per_article]
        qs.extend(art_qs)
    mids = sorted({c.material_id for c in chunks})
    for mi, mid in enumerate(mids):
        foreign = [q for q in pool_answerable if q.material_id != mid]
        split = "dev" if int(mid[2:]) % 2 == 0 else "test"
        for k, src in enumerate(rng.sample(foreign, min(off_topic_per_article, len(foreign)))):
            qs.append(Question(f"off_{mid}_{k}", src.question, OFF_TOPIC, mid, "0", [], None, None,
                               split, "squad_offtopic", meta={"source_qid": src.qid}))
    return Corpus(chunks), qs


# -------------------------------------------------------------- persist

def save_questions(path, qs: Iterable[Question]) -> int:
    return write_jsonl(path, (q.to_json() for q in qs))


def load_questions(path) -> List[Question]:
    return [Question.from_json(d) for d in read_jsonl(path)]
