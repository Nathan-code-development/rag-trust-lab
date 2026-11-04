"""Run the ragtrust isolation suite against one app via its adapter.

    python kit/run_app_suite.py \
        --adapter kit/adapters/open_webui.py --class OpenWebUIAdapter \
        --base http://127.0.0.1:3000 \
        --echo-log /tmp/echo_prompts.jsonl \
        --data-dir /path/to/app/vector_store   (optional; omit to skip S6) \
        --version 0.8.11 \
        --out results/open-webui.json

Loads the adapter by file path (so an adapter file named like an installed
package does not collide), constructs it with a fresh CanaryRegistry, runs the
suite, and writes a per-app report. Exit code = number of failed checks.
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ragtrust.isolation.canary import CanaryRegistry  # noqa: E402
from ragtrust.isolation.suite import run_suite  # noqa: E402


def load_adapter_class(path, class_name):
    spec = importlib.util.spec_from_file_location("ragtrust_adapter_mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if class_name:
        return getattr(mod, class_name)
    # else: first class ending in 'Adapter'
    cands = [v for k, v in vars(mod).items() if k.endswith("Adapter") and isinstance(v, type)]
    if not cands:
        raise SystemExit(f"no *Adapter class found in {path}; pass --class")
    return cands[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--class", dest="cls", default=None)
    ap.add_argument("--base", required=True)
    ap.add_argument("--echo-log", required=True)
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--version", default="?")
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()

    Adapter = load_adapter_class(a.adapter, a.cls)
    Path(a.echo_log).parent.mkdir(parents=True, exist_ok=True)
    Path(a.echo_log).write_text("", encoding="utf-8")   # clean attribution window
    reg = CanaryRegistry(seed=a.seed)
    app = Adapter(a.base, a.echo_log, reg, data_dir=a.data_dir, version=a.version)
    R = run_suite(app, reg)
    j = R.to_json()
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(j, indent=2), encoding="utf-8")

    print(json.dumps({"app": j["app"], "n_checks": j["n_checks"], "n_fail": j["n_fail"],
                      "failed": R.failed()}, indent=2))
    print("\nper-check:")
    for c in j["checks"]:
        flag = "FAIL" if c["status"] == "FAIL" else c["status"]
        print(f"  {flag:4} {c['id']:30} ({c['scenario']})"
              + (f"  {c['detail'][:90]}" if c["status"] == "FAIL" else ""))
    if j["n_fail"]:
        print("\n⚠ FAIL = candidate isolation issue. VERIFY MANUALLY, then disclose to the "
              "maintainer before publishing. See kit/README.md.")
    sys.exit(min(j["n_fail"], 120))


if __name__ == "__main__":
    main()
