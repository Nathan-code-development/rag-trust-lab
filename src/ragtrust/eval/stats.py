"""Statistical tests for small benchmarks.

With 60 answerable questions a 13-point Rank-1 gap is 8 questions; reviewers
will ask whether that is significant. Every headline comparison in the paper
should carry a 95% CI and a paired test from this module.
"""

from __future__ import annotations

import math
import random
from typing import Callable, Dict, List, Sequence, Tuple


def bootstrap_ci(values: Sequence[float], stat: Callable[[Sequence[float]], float] = None,
                 n_boot: int = 10_000, alpha: float = 0.05, seed: int = 13) -> Tuple[float, float, float]:
    """Percentile bootstrap over questions. Returns (point, lo, hi)."""
    stat = stat or (lambda v: sum(v) / len(v))
    vals = list(values)
    if not vals:
        return float("nan"), float("nan"), float("nan")
    rng = random.Random(seed)
    n = len(vals)
    boots = sorted(stat([vals[rng.randrange(n)] for _ in range(n)]) for _ in range(n_boot))
    lo = boots[int((alpha / 2) * n_boot)]
    hi = boots[min(n_boot - 1, int((1 - alpha / 2) * n_boot))]
    return stat(vals), lo, hi


def paired_bootstrap(a: Sequence[float], b: Sequence[float], n_boot: int = 10_000,
                     seed: int = 13) -> Dict[str, float]:
    """CI on mean(b - a) and a two-sided bootstrap p-value (Koehn-style)."""
    assert len(a) == len(b)
    d = [y - x for x, y in zip(a, b)]
    n = len(d)
    if n == 0:
        return {"delta": float("nan")}
    rng = random.Random(seed)
    obs = sum(d) / n
    boots = []
    for _ in range(n_boot):
        boots.append(sum(d[rng.randrange(n)] for _ in range(n)) / n)
    boots.sort()
    # p: how often the resampled delta crosses zero on the other side
    if obs >= 0:
        p = 2 * sum(1 for x in boots if x <= 0) / n_boot
    else:
        p = 2 * sum(1 for x in boots if x >= 0) / n_boot
    return {"delta": obs, "lo": boots[int(0.025 * n_boot)], "hi": boots[int(0.975 * n_boot)],
            "p": min(1.0, p), "n": n}


def paired_permutation(a: Sequence[float], b: Sequence[float], n_perm: int = 20_000,
                       seed: int = 13) -> float:
    """Two-sided sign-flip permutation test on mean(b - a). Exact if n small."""
    d = [y - x for x, y in zip(a, b)]
    nz = [x for x in d if x != 0]
    if not nz:
        return 1.0
    obs = abs(sum(d))
    if len(nz) <= 16:
        cnt = tot = 0
        for mask in range(1 << len(nz)):
            s = sum(x if (mask >> i) & 1 else -x for i, x in enumerate(nz))
            tot += 1
            cnt += abs(s) >= obs - 1e-12
        return cnt / tot
    rng = random.Random(seed)
    cnt = 0
    for _ in range(n_perm):
        s = sum(x if rng.random() < 0.5 else -x for x in nz)
        cnt += abs(s) >= obs - 1e-12
    return (cnt + 1) / (n_perm + 1)


def mcnemar_exact(a: Sequence[bool], b: Sequence[bool]) -> Dict[str, float]:
    """Exact McNemar for paired binary outcomes (e.g. Rank-1 hit per question)."""
    b01 = sum(1 for x, y in zip(a, b) if not x and y)
    b10 = sum(1 for x, y in zip(a, b) if x and not y)
    n = b01 + b10
    if n == 0:
        return {"b01": 0, "b10": 0, "p": 1.0}
    k = min(b01, b10)
    p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return {"b01": b01, "b10": b10, "p": min(1.0, 2 * p)}


def wilson_ci(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """For proportions like 3/60 false refusals or 10/10 blocked."""
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return max(0.0, c - h), min(1.0, c + h)


def holm(pvals: Dict[str, float]) -> Dict[str, float]:
    """Holm–Bonferroni adjustment for the family of comparisons in one table."""
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(items)
    adj, running = {}, 0.0
    for i, (k, p) in enumerate(items):
        running = max(running, min(1.0, (m - i) * p))
        adj[k] = running
    return adj


def cohen_kappa(a: Sequence, b: Sequence) -> float:
    """Inter-annotator agreement for the second-annotator relabelling task."""
    assert len(a) == len(b) and a
    labels = sorted(set(a) | set(b))
    n = len(a)
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    pe = sum((sum(1 for x in a if x == l) / n) * (sum(1 for y in b if y == l) / n) for l in labels)
    return (po - pe) / (1 - pe) if pe < 1 else 1.0
