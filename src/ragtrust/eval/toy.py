"""Synthetic course benchmark for smoke tests and CI.

It deliberately contains the three question classes of the real benchmark,
including on-topic unanswerable questions whose key phrase recurs in the
material while the asked-for fact is absent (the 0.987 case). Numbers on this
toy set mean nothing scientifically — they only prove the pipeline runs.
"""

from __future__ import annotations

import random
from typing import List, Tuple

from ..corpus import Corpus, chunk_text_words
from ..types import ANSWERABLE, OFF_TOPIC, ON_TOPIC_UNANSWERABLE, Chunk, Question

_FACTS = {
    "ai_ethics": [
        ("Floridi", "proposed the principle of explicability as the fifth principle of AI ethics"),
        ("the census date", "is the last day students may withdraw without financial penalty"),
        ("the assessment weighting", "for the reflective journal is worth 10% of the final grade"),
        ("rival AI corporations", "compete for talent and compute, a theme repeated across the lecture"),
        ("beneficence", "requires that AI systems promote wellbeing and preserve dignity"),
        ("non-maleficence", "asks designers to prevent harm including privacy violations"),
    ],
    "networks": [
        ("TCP", "uses a three-way handshake of SYN, SYN-ACK and ACK to open a connection"),
        ("UDP", "is connectionless and offers no delivery guarantee"),
        ("the subnet mask", "255.255.255.0 leaves 254 usable host addresses"),
        ("routing tables", "store the next hop for each destination prefix"),
        ("DNS", "resolves domain names to IP addresses using a hierarchy of servers"),
        ("congestion control", "reduces the sending window when packet loss is detected"),
    ],
    "game_design": [
        ("Final Fantasy XVI", "was cited as an example of an action-oriented JRPG combat system"),
        ("Connor Kenway", "is the protagonist used to discuss open-world narrative pacing"),
        ("level design", "guides the player using landmarks, lighting and sightlines"),
        ("playtesting", "should start early with paper prototypes"),
        ("game loops", "combine a core action, a reward and a reason to repeat"),
        ("difficulty curves", "should rise with short rests after each challenge spike"),
    ],
}

_FILLER = ("This section of the lecture revisits earlier material and connects it to the weekly "
           "readings. Students are encouraged to take notes and compare examples across topics. ")


def build_toy(seed: int = 7) -> Tuple[Corpus, List[Question]]:
    rng = random.Random(seed)
    chunks, qs = [], []
    owners = {"1": ["ai_ethics", "networks"], "2": ["game_design"]}
    mid_of = {}
    n = 0
    for owner, topics in owners.items():
        for t in topics:
            n += 1
            mid = str(n)
            mid_of[t] = (owner, mid)
            body = []
            for subj, pred in _FACTS[t]:
                body.append(f"{subj[0].upper() + subj[1:]} {pred}. " + _FILLER * rng.randint(3, 6))
            if t == "ai_ethics":   # key phrase recurs, answer (the five names) never given
                body.append("The rival AI corporations theme returns here: rival AI corporations "
                            "shape regulation, and rival AI corporations shape public trust. " + _FILLER * 4)
            text = " ".join(body)
            for i, c in enumerate(chunk_text_words(text, size=60, overlap=20)):
                chunks.append(Chunk(f"{mid}_{i}", c, mid, owner, f"{t}.pdf", i // 2 + 1, i))
    corpus = Corpus(chunks)

    qn = 0

    def add(q, cls, owner, mid, gold_sub=None, qtype=None):
        nonlocal qn
        qn += 1
        gold = []
        if gold_sub:
            gold = [c.chunk_id for c in corpus.scope(owner, [mid]) if gold_sub.lower() in c.text.lower()]
        split = "holdout" if qn % 5 == 0 else "dev"
        qs.append(Question(f"T{qn:03d}", q, cls, mid, owner, gold, None, None, split, qtype))

    for t, facts in _FACTS.items():
        owner, mid = mid_of[t]
        for subj, pred in facts:
            if subj == "rival AI corporations":
                continue
            add(f"What does the lecture say about {subj}?", ANSWERABLE, owner, mid, pred[:40], "entity")
            words = pred.split()
            add(f"Which idea {' '.join(words[1:5])} is discussed?", ANSWERABLE, owner, mid, pred[:40], "paraphrase")
    eo, em = mid_of["ai_ethics"]
    add("Name the five rival AI corporations listed in the lecture.", ON_TOPIC_UNANSWERABLE, eo, em)
    add("What year was the principle of explicability adopted into law?", ON_TOPIC_UNANSWERABLE, eo, em)
    no, nm = mid_of["networks"]
    add("What is the default TCP port for the course's lab server?", ON_TOPIC_UNANSWERABLE, no, nm)
    go, gm = mid_of["game_design"]
    add("How many copies did Final Fantasy XVI sell in its first week?", ON_TOPIC_UNANSWERABLE, go, gm)
    for q, (o, m) in [("What is the boiling point of ethanol?", mid_of["networks"]),
                      ("Who painted the Mona Lisa?", mid_of["ai_ethics"]),
                      ("How do I bake sourdough bread?", mid_of["game_design"]),
                      ("What is the capital of Australia?", mid_of["networks"])]:
        add(q, OFF_TOPIC, o, m)
    return corpus, qs
