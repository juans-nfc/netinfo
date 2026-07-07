#!/usr/bin/env bash
#
# deploy.sh - set up and launch the netinv web UI.
#
# What it does:
#   1. creates a Python venv and installs dependencies
#   2. warns about missing optional system tools (snmp, nmap)
#   3. makes sure a config.yaml and an initialized database exist
#   4. finds a free TCP port (so it won't collide with anything already running)
#   5. launches the UI (gunicorn if available, else the built-in server)
#   6. writes a ready-to-install systemd unit with the chosen port baked in
#
# Usage:
#   ./deploy.sh                 # auto-pick a port, bind to 0.0.0.0, run in foreground
#   PORT=8090 ./deploy.sh       # force a specific port (still checked for conflicts)
#   HOST=127.0.0.1 ./deploy.sh  # bind to localhost only (recommended, reach via SSH)
#   ./deploy.sh --setup-only    # provision + pick port + write unit, but don't launch
#
set -euo pipefail
cd "$(dirname "$0")"
HOST="${HOST:-0.0.0.0}"
SETUP_ONLY=0
[ "${1:-}" = "--setup-only" ] && SETUP_ONLY=1

say(){ printf '\033[1;36m[deploy]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "python3 is required."

# --- 1. venv + deps --------------------------------------------------------
if [ ! -d .venv ]; then
  say "creating virtualenv (.venv)"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
say "installing Python dependencies"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
# ensure the web server bits are present even if requirements.txt is trimmed
pip install --quiet flask gunicorn || pip install --quiet flask

# --- 2. optional system tools ---------------------------------------------
command -v snmpget >/dev/null 2>&1 || warn "net-snmp not found - SNMP collection (switches/printers) will be skipped. Install with: apt install snmp"
command -v nmap    >/dev/null 2>&1 || warn "nmap not found - OS fingerprinting of odd devices disabled (optional)."

# --- 3. config + database --------------------------------------------------
if [ ! -f config.yaml ]; then
  cp config.example.yaml config.yaml
  warn "created config.yaml from the example - EDIT IT and add your credentials before scanning."
fi
say "initializing database schema"
python3 -c "import store; store.connect('inventory.db').__enter__()" >/dev/null 2>&1 || \
  python3 - <<'PY'
import store
with store.connect('inventory.db'):
    pass
PY

# --- 4. find a free port ---------------------------------------------------
say "selecting a free port"
PORT="$(PORT="${PORT:-}" python3 - <<'PY'
import os, socket, sys
prefer = [8080, 8000, 8888, 5000, 8008, 8081, 8082, 9000, 9090]
def free(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("0.0.0.0", p)); return True
    except OSError:
        return False
    finally:
        s.close()
want = os.environ.get("PORT")
cands = ([int(want)] if want else []) + prefer + list(range(8083, 8400))
for p in cands:
    if free(p):
        print(p); break
else:
    sys.exit(1)
PY
)" || die "could not find a free port in the searched range."
say "using port $PORT (host $HOST)"

# --- 5. write a systemd unit (not installed automatically) -----------------
UNIT="netinv-web.service"
GUNICORN="$(pwd)/.venv/bin/gunicorn"
if [ -x "$GUNICORN" ]; then
  EXEC="$GUNICORN -w 1 -b ${HOST}:${PORT} app:app"
else
  EXEC="$(pwd)/.venv/bin/python app.py --host ${HOST} --port ${PORT}"
fi
cat > "$UNIT" <<EOF
[Unit]
Description=netinv web UI
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$(pwd)
Environment=NETINV_DB=$(pwd)/inventory.db
Environment=NETINV_CONFIG=$(pwd)/config.yaml
ExecStart=${EXEC}
Restart=on-failure
User=$(whoami)

[Install]
WantedBy=multi-user.target
EOF
say "wrote ${UNIT} (port ${PORT}). To run it persistently:"
echo "      sudo cp ${UNIT} /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now netinv-web"

# --- 6. launch now ---------------------------------------------------------
if [ "$SETUP_ONLY" = "1" ]; then
  say "setup complete (--setup-only). Start it with: ${EXEC}"
  exit 0
fi
say "starting UI -> http://${HOST}:${PORT}  (Ctrl-C to stop)"
[ "$HOST" = "0.0.0.0" ] && warn "bound to 0.0.0.0 with NO authentication - firewall it or set HOST=127.0.0.1 and use an SSH tunnel."
exec ${EXEC}
