"""Run the generic ragtrust isolation suite against a local Open WebUI instance.

Usage: owui python run_suite_owui.py <base_url> <echo_log> <data_dir> <version> <out.json>
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from owui_adapter import OpenWebUIAdapter  # noqa: E402
from ragtrust.isolation.canary import CanaryRegistry  # noqa: E402
from ragtrust.isolation.suite import run_suite  # noqa: E402


def main():
    base, echo_log, data_dir, version, out = sys.argv[1:6]
    # fresh echo log for a clean attribution window
    Path(echo_log).write_text("", encoding="utf-8")
    reg = CanaryRegistry(seed=11)
    app = OpenWebUIAdapter(base, echo_log, reg, data_dir=data_dir, version=version)
    R = run_suite(app, reg)
    j = R.to_json()
    Path(out).write_text(json.dumps(j, indent=2), encoding="utf-8")
    print(json.dumps({"app": j["app"], "n_checks": j["n_checks"], "n_fail": j["n_fail"],
                      "failed": R.failed()}, indent=2))
    # print per-scenario pass/fail
    for c in j["checks"]:
        print(f"  {c['status']:4} {c['id']:34} ({c['scenario']})  {c['detail'][:80] if c['status']=='FAIL' else ''}")


if __name__ == "__main__":
    main()
