# E-A3 seeded-fault detection (one fault per class, controlled app)

Detection matrix (check = class detected; dot = missed):

| Method | D1 | D2 | D3 | D4 | D5 | Recall | FP(clean) |
|---|---|---|---|---|---|---|---|
| canary_echo(ours) | ✓ | ✓ | ✓ | ✓ | ✓ | 100% | none |
| idor_baseline | · | · | · | · | ✓ | 20% | none |
| static_keying | ✓ | ✓ | ✓ | ✓ | · | 80% | none |

Precision: who false-positives on the owner-less-but-runtime-guarded (safe) case:

- canary_echo(ours): none (correct)
- idor_baseline: none (correct)
- static_keying: D1 (false positive)

Over-flagging (classes flagged beyond the seeded one):

- canary_echo(ours): none
- idor_baseline: none
- static_keying: none
