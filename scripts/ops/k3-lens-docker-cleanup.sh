#!/usr/bin/env bash
set -euo pipefail

# Guarded Docker cleanup for the K3 Lens droplet.
# Runs only when root filesystem free space is below FREE_THRESHOLD_PCT.
# Safe scope: Docker builder cache and unused Docker images only.
# Never prunes volumes, containers, secrets, or application data directories.

ROOT_PATH="${ROOT_PATH:-/}"
FREE_THRESHOLD_PCT="${FREE_THRESHOLD_PCT:-25}"
BUILDER_KEEP_STORAGE="${BUILDER_KEEP_STORAGE:-8GB}"
LOG_FILE="${LOG_FILE:-/var/log/k3-lens-docker-cleanup.log}"
DRY_RUN=0
FORCE=0

usage() {
  cat <<'USAGE'
Usage: k3-lens-docker-cleanup.sh [--dry-run] [--force]

Options:
  --dry-run  Report what would happen without pruning.
  --force    Run cleanup regardless of free-space threshold.

Environment:
  ROOT_PATH=/                 Filesystem to check.
  FREE_THRESHOLD_PCT=25       Cleanup threshold; run when free space is below this percent.
  BUILDER_KEEP_STORAGE=8GB    BuildKit cache to keep when pruning.
  LOG_FILE=/var/log/...       Log destination.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed or not in PATH" >&2
  exit 1
fi

if ! df -P "$ROOT_PATH" >/dev/null 2>&1; then
  echo "cannot inspect filesystem: $ROOT_PATH" >&2
  exit 1
fi

free_pct=$(df -P "$ROOT_PATH" | awk 'NR==2 { gsub(/%/, "", $5); print 100 - $5 }')
used_pct=$(df -P "$ROOT_PATH" | awk 'NR==2 { gsub(/%/, "", $5); print $5 }')

log() {
  printf '%s %s\n' "$(date --iso-8601=seconds)" "$*" | tee -a "$LOG_FILE"
}

mkdir -p "$(dirname "$LOG_FILE")"

{
  flock -n 9 || { log "another cleanup run is already active; exiting"; exit 0; }

  log "start root=${ROOT_PATH} used=${used_pct}% free=${free_pct}% threshold_free_below=${FREE_THRESHOLD_PCT}% dry_run=${DRY_RUN} force=${FORCE}"
  docker system df | sed 's/^/docker-system-df-before: /' | tee -a "$LOG_FILE" >/dev/null || true

  if (( FORCE == 0 && free_pct >= FREE_THRESHOLD_PCT )); then
    log "skip: free space ${free_pct}% is not below ${FREE_THRESHOLD_PCT}%"
    exit 0
  fi

  if (( DRY_RUN == 1 )); then
    log "dry-run: would run docker builder prune -af --keep-storage ${BUILDER_KEEP_STORAGE}"
    log "dry-run: would run docker image prune -af"
    exit 0
  fi

  log "running: docker builder prune -af --keep-storage ${BUILDER_KEEP_STORAGE}"
  docker builder prune -af --keep-storage "${BUILDER_KEEP_STORAGE}" 2>&1 | sed 's/^/builder-prune: /' | tee -a "$LOG_FILE" >/dev/null

  log "running: docker image prune -af"
  docker image prune -af 2>&1 | sed 's/^/image-prune: /' | tee -a "$LOG_FILE" >/dev/null

  docker system df | sed 's/^/docker-system-df-after: /' | tee -a "$LOG_FILE" >/dev/null || true
  df -h "$ROOT_PATH" | sed 's/^/df-after: /' | tee -a "$LOG_FILE" >/dev/null || true
  log "done"
} 9>/run/k3-lens-docker-cleanup.lock
