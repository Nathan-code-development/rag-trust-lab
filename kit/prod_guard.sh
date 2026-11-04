#!/usr/bin/env bash
# Production-host safety guard: source it before running tests.  Usage: source prod_guard.sh
# What it does: (1) abort if free disk is below a floor; (2) clean up ONLY our own things by
# name/tag, never touching your production docker.
#
# Key safety conventions (please follow):
#   - This script NEVER runs `docker system prune` (that would delete your production unused images!).
#   - All our test containers are prefixed ragtest- ; cleanup only removes those.
#   - Remove a test image individually by tag with `rmi_test <image:tag>`, nothing else.

FLOOR_GB="${FLOOR_GB:-6}"   # minimum free space always reserved for the system/production (GB)

free_gb(){ echo $(( $(df -P / | awk 'NR==2{print $4}') / 1024 / 1024 )); }

need_disk(){   # need_disk <GB>  returns 0 if enough, aborts (returns 1) if not
  local need="$1" f; f=$(free_gb)
  if [ "$f" -lt "$need" ] || [ "$f" -lt "$FLOOR_GB" ]; then
    echo "x Not enough disk: ${f}GB free, need ${need}GB and no lower than the floor ${FLOOR_GB}GB. Clean up first."; return 1
  fi
  echo "ok Disk OK: ${f}GB free (need ${need}GB)"; return 0
}

stop_test(){   # stop and remove all ragtest- containers (ours only)
  local ids; ids=$(docker ps -aq --filter "name=ragtest-")
  [ -n "$ids" ] && docker rm -f $ids || echo "(no ragtest- containers)"
}

rmi_test(){    # rmi_test <image:tag>  remove the specified test image only
  [ -n "$1" ] && docker rmi "$1" 2>/dev/null && echo "removed image $1 (free $(free_gb)GB)" || echo "(image $1 missing or still in use)"
}

guard_status(){ echo "free $(free_gb)GB | test containers: $(docker ps -aq --filter name=ragtest- | wc -l)"; }

echo "prod_guard loaded. FLOOR_GB=${FLOOR_GB}. commands: need_disk <GB> / stop_test / rmi_test <img> / guard_status / free_gb"
echo "This host may be a production server: never run 'docker system prune'; clean up only our own things with stop_test / rmi_test."
