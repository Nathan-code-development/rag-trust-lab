PY ?= python3

.PHONY: reproduce rq3 rq3-multiseed rq2-kappa clean

reproduce:          ## verify every deterministic paper number (RQ2 kappa, RQ3) -> ALL CHECKS PASSED (17/17)
	$(PY) scripts/reproduce_deterministic.py

rq3:                ## RQ3 Table V: canonical single-fault run (100 / 20 / 80)
	$(PY) studies/ea3_seeded/run_ea3.py

rq3-multiseed:      ## RQ3 Table VI: N=1000 randomized trials (canary-echo 99.3% [99.0,99.5])
	$(PY) studies/ea3_seeded/run_ea3_multiseed.py 1000

rq2-kappa:          ## RQ2: inter-coder Cohen's kappa = 0.458
	$(PY) studies/ea2_history/kappa/compute_kappa.py

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
