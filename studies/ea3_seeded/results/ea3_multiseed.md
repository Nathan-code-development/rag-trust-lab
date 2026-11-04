# E-A3 multi-seed robustness (N = 1000 independent randomized trials per configuration)

Each trial: fresh canary tokens + randomized document content (section count, marker positions, vocabulary) + randomized worker count (2-4). Same three detectors.

## Per-class detection rate (fraction of N trials in which the sole seeded class is detected)

| Method | D1 | D2 | D3 | D4 | D5 |
|---|---|---|---|---|---|
| canary_echo(ours) | 99% | 99% | 98% | 100% | 100% |
| idor_baseline | 0% | 0% | 0% | 0% | 100% |
| static_keying | 100% | 100% | 100% | 100% | 0% |

## Aggregate recall over 5 classes x N trials (Wilson 95% CI)

| Method | recall | 95% CI | k/n |
|---|---|---|---|
| canary_echo(ours) | 99.3% | [99.0%, 99.5%] | 4965/5000 |
| idor_baseline | 20.0% | [18.9%, 21.1%] | 1000/5000 |
| static_keying | 80.0% | [78.9%, 81.1%] | 4000/5000 |

## False-positive rate

| Method | clean app | guarded-but-owner-less (D1 FP) |
|---|---|---|
| canary_echo(ours) | 0.0% | 0.0% |
| idor_baseline | 0.0% | 0.0% |
| static_keying | 0.0% | 100.0% |

## Over-flagging (trials flagging any class beyond the seeded one)

- canary_echo(ours): 0 / 5000 class-trials
- idor_baseline: 0 / 5000 class-trials
- static_keying: 0 / 5000 class-trials
