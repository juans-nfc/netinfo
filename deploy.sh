#!/usr/bin/env bash
#
# NetView deployment script.
#
#   ./deploy.sh            build the image and (re)start the stack
#   ./deploy.sh status     show container + health status
#   ./deploy.sh logs       follow container logs
#   ./deploy.sh restart    recreate the container without rebuilding
#   ./deploy.sh rollback   revert to the previously deployed image
#   ./deploy.sh down       stop and remove the stack
#   ./deploy.sh help       this message
#
# Safe to re-run. Each deploy keeps the prior image as netview:previous so a
# single-step rollback is always available.

set -euo pipefail

# --- locate project (this script's directory) -------------------------------
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE="netview"
SERVICE="netview"
ENV_FILE=".env"
ENV_EXAMPLE=".env.example"

# --- pretty output ----------------------------------------------------------
if [[ -t 1 ]]; then
  C_B="\033[1m"; C_G="\033[32m"; C_Y="\033[33m"; C_R="\033[31m"; C_C="\033[36m"; C_0="\033[0m"
else
  C_B=""; C_G=""; C_Y=""; C_R=""; C_C=""; C_0=""
fi
log()  { printf "${C_C}▸${C_0} %s\n" "$*"; }
ok()   { printf "${C_G}✓${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}!${C_0} %s\n" "$*" >&2; }
die()  { printf "${C_R}✗ %s${C_0}\n" "$*" >&2; exit 1; }

# --- docker compose detection ----------------------------------------------
if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  die "docker compose is not installed."
fi
command -v docker >/dev/null 2>&1 || die "docker is not installed."

# --- read a value from .env, stripping inline comments and quotes ----------
# (compose reads .env itself; this is only for the few values the script needs)
read_env() {
  local key="$1" default="${2:-}" line val
  [[ -f "$ENV_FILE" ]] || { printf '%s' "$default"; return; }
  line="$(grep -E "^[[:space:]]*${key}=" "$ENV_FILE" | tail -n1 || true)"
  [[ -n "$line" ]] || { printf '%s' "$default"; return; }
  val="${line#*=}"
  val="${val%%$'\r'}"          # strip CR (Windows line endings)
  val="${val%% #*}"            # strip trailing " # comment"
  val="${val#"${val%%[![:space:]]*}"}"   # ltrim
  val="${val%"${val##*[![:space:]]}"}"   # rtrim
  val="${val%\"}"; val="${val#\"}"       # unquote "
  val="${val%\'}"; val="${val#\'}"       # unquote '
  printf '%s' "${val:-$default}"
}

# --- generate a random hex secret without depending on any one tool --------
gen_secret() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32
  elif command -v python3 >/dev/null 2>&1; then python3 -c "import secrets;print(secrets.token_hex(32))"
  else head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# ===========================================================================
# subcommands
# ===========================================================================
cmd_status() {
  "${DC[@]}" ps
  local port cid state health
  port="$(read_env NETVIEW_PORT 8850)"
  cid="$("${DC[@]}" ps -q "$SERVICE" 2>/dev/null || true)"
  if [[ -n "$cid" ]]; then
    state="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$cid" 2>/dev/null || echo n/a)"
    printf "\nstate: ${C_B}%s${C_0}   health: ${C_B}%s${C_0}   url: http://127.0.0.1:%s/\n" "$state" "$health" "$port"
  fi
}

cmd_logs()    { "${DC[@]}" logs -f --tail=200 "$SERVICE"; }
cmd_restart() { log "Recreating container…"; "${DC[@]}" up -d --force-recreate "$SERVICE"; wait_healthy; }
cmd_down()    { log "Stopping stack…"; "${DC[@]}" down; ok "Stopped."; }

cmd_rollback() {
  if ! docker image inspect "${IMAGE}:previous" >/dev/null 2>&1; then
    die "No ${IMAGE}:previous image to roll back to."
  fi
  log "Rolling back ${IMAGE}:latest → previous build…"
  # swap current and previous so a rollback is itself reversible
  docker image inspect "${IMAGE}:latest" >/dev/null 2>&1 && docker tag "${IMAGE}:latest" "${IMAGE}:rollback-tmp"
  docker tag "${IMAGE}:previous" "${IMAGE}:latest"
  if docker image inspect "${IMAGE}:rollback-tmp" >/dev/null 2>&1; then
    docker tag "${IMAGE}:rollback-tmp" "${IMAGE}:previous"
    docker rmi "${IMAGE}:rollback-tmp" >/dev/null 2>&1 || true
  fi
  "${DC[@]}" up -d --force-recreate --no-build "$SERVICE"
  wait_healthy
  ok "Rolled back."
}

# --- health gate ------------------------------------------------------------
wait_healthy() {
  local port; port="$(read_env NETVIEW_PORT 8850)"
  local url="http://127.0.0.1:${port}/healthz"
  local fetch=""
  if command -v curl >/dev/null 2>&1; then fetch="curl -fsS -m 3 -o /dev/null"
  elif command -v wget >/dev/null 2>&1; then fetch="wget -q -T 3 -O /dev/null"
  fi
  if [[ -z "$fetch" ]]; then
    warn "Neither curl nor wget found; skipping health check. Try: $url"
    return 0
  fi
  log "Waiting for $url …"
  for i in $(seq 1 30); do
    if $fetch "$url" 2>/dev/null; then ok "Healthy (${i}s)."; return 0; fi
    sleep 1
  done
  warn "Health check did not pass within 30s. Recent logs:"
  "${DC[@]}" logs --tail=40 "$SERVICE" || true
  die "Deployment unhealthy. Fix the issue, or run: ./deploy.sh rollback"
}

# --- main deploy ------------------------------------------------------------
cmd_deploy() {
  # .env
  if [[ ! -f "$ENV_FILE" ]]; then
    [[ -f "$ENV_EXAMPLE" ]] || die "Missing $ENV_FILE and $ENV_EXAMPLE."
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    warn "Created $ENV_FILE from $ENV_EXAMPLE — review subnets and MeshCentral settings (or set them later in the UI)."
  fi

  # secret key: generate one if blank so stored credentials survive restarts
  if [[ -z "$(read_env NETVIEW_SECRET_KEY)" ]]; then
    local secret; secret="$(gen_secret)"
    cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    if grep -qE '^[[:space:]]*NETVIEW_SECRET_KEY=' "$ENV_FILE"; then
      # portable in-place edit (GNU + BSD sed)
      sed -i.tmp "s|^[[:space:]]*NETVIEW_SECRET_KEY=.*|NETVIEW_SECRET_KEY=${secret}|" "$ENV_FILE" && rm -f "${ENV_FILE}.tmp"
    else
      printf '\nNETVIEW_SECRET_KEY=%s\n' "$secret" >> "$ENV_FILE"
    fi
    ok "Generated NETVIEW_SECRET_KEY (backup saved as ${ENV_FILE}.bak.*)."
  fi

  [[ -n "$(read_env NETVIEW_SUBNETS)" ]] || warn "NETVIEW_SUBNETS is empty — set subnets here or under Settings in the UI before scanning."

  mkdir -p data   # bind-mounted to /app/data

  # keep the current image as the rollback target
  if docker image inspect "${IMAGE}:latest" >/dev/null 2>&1; then
    docker tag "${IMAGE}:latest" "${IMAGE}:previous"
    log "Tagged current image as ${IMAGE}:previous (rollback target)."
  fi

  log "Building image…"
  "${DC[@]}" build

  log "Starting stack…"
  "${DC[@]}" up -d --force-recreate

  wait_healthy

  local port root; port="$(read_env NETVIEW_PORT 8850)"; root="$(read_env NETVIEW_ROOT_PATH)"
  echo
  ok "NetView deployed."
  printf "   local:  ${C_B}http://127.0.0.1:%s/${C_0}\n" "$port"
  [[ -n "$root" ]] && printf "   proxied: behind nginx at ${C_B}%s/${C_0} (see nginx-netview.conf.example)\n" "$root"
  printf "   logs:   ${C_B}./deploy.sh logs${C_0}    rollback: ${C_B}./deploy.sh rollback${C_0}\n"

  docker image prune -f >/dev/null 2>&1 || true
}

# ===========================================================================
case "${1:-deploy}" in
  ""|deploy)        cmd_deploy ;;
  status|ps)        cmd_status ;;
  logs)             cmd_logs ;;
  restart)          cmd_restart ;;
  rollback)         cmd_rollback ;;
  down|stop)        cmd_down ;;
  help|-h|--help)   awk 'NR==1{next} /^#/{sub(/^# ?/,"");print;next} {exit}' "$0" ;;
  *)                die "Unknown command: $1  (try: ./deploy.sh help)" ;;
esac
