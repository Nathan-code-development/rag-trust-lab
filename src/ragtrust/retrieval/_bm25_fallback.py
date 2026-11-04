"""BM25Okapi-compatible fallback (vendored from production). NOT bit-identical to rank_bm25; results produced with it must not be reported as the frozen system."""

from __future__ import annotations

import math
from collections import Counter


class BM25Okapi:
    def __init__(self, corpus, k1=1.5, b=0.75, epsilon=0.25):
        self.corpus = [list(document) for document in corpus]
        self.k1 = float(k1)
        self.b = float(b)
        self.doc_len = [len(document) for document in self.corpus]
        self.avgdl = sum(self.doc_len) / len(self.doc_len) if self.doc_len else 0.0
        self.term_freqs = [Counter(document) for document in self.corpus]

        document_frequency = Counter()
        for frequencies in self.term_freqs:
            document_frequency.update(frequencies.keys())

        size = len(self.corpus)
        raw_idf = {
            term: math.log(size - count + 0.5) - math.log(count + 0.5)
            for term, count in document_frequency.items()
        }
        average_idf = sum(raw_idf.values()) / len(raw_idf) if raw_idf else 0.0
        floor = float(epsilon) * average_idf
        self.idf = {term: (value if value >= 0 else floor) for term, value in raw_idf.items()}

    def get_scores(self, query_tokens):
        scores = []
        for index, frequencies in enumerate(self.term_freqs):
            length = self.doc_len[index]
            normalizer = 1.0 - self.b
            if self.avgdl:
                normalizer += self.b * length / self.avgdl
            score = 0.0
            for term in query_tokens:
                frequency = frequencies.get(term, 0)
                if not frequency:
                    continue
                numerator = frequency * (self.k1 + 1.0)
                denominator = frequency + self.k1 * normalizer
                score += self.idf.get(term, 0.0) * numerator / denominator
            scores.append(score)
        return scores
