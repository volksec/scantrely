#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5000}"
mkdir -p "$ROOT_DIR/logs"
LOG_FILE="${LOG_FILE:-$ROOT_DIR/logs/server.log}"
PID_FILE="${PID_FILE:-$ROOT_DIR/logs/server.pid}"

cd "$ROOT_DIR"

# Adaptive VPS profile. utils/resource_profile.py detects CPU/RAM/swap and
# emits conservative defaults for workers, tool gates, and watchdog thresholds.
# Any ASM_* variable already exported by the operator still wins.
if [[ "${ASM_AUTO_PROFILE:-1}" != "0" ]]; then
  eval "$(python3 -m utils.resource_profile)"
else
  # ── Read settings.json overrides (lower priority than explicit env vars) ──
  if [[ -f "$SCRIPT_DIR/config/settings.json" ]]; then
    _load_setting() {
      local key="$1" env_var="$2" default="$3"
      local val="${!env_var:-}"
      if [[ -z "$val" ]]; then
        val=$(python3 -c "import json;d=json.load(open('$SCRIPT_DIR/config/settings.json'));print(d.get('$key',''))" 2>/dev/null || echo "")
      fi
      export "$env_var"="${val:-$default}"
    }
    _load_setting "asm_job_workers"        "ASM_JOB_WORKERS"         "1"
    _load_setting "asm_global_proc_limit"  "ASM_GLOBAL_PROC_LIMIT"   "6"
    _load_setting "asm_domain_fanout"      "ASM_DOMAIN_FANOUT_WORKERS" "3"
    _load_setting "asm_gate_default"       "ASM_GATE_DEFAULT"        "3"
    _load_setting "asm_watchdog_max_load"  "ASM_WATCHDOG_MAX_LOAD"   "4"
    _load_setting "asm_watchdog_min_mem_mb" "ASM_WATCHDOG_MIN_MEM_MB" "1536"
    _load_setting "asm_watchdog_max_procs" "ASM_WATCHDOG_MAX_RECON_PROCS" "10"
  fi
  export ASM_JOB_WORKERS="${ASM_JOB_WORKERS:-1}"
  export ASM_GLOBAL_PROC_LIMIT="${ASM_GLOBAL_PROC_LIMIT:-6}"
  export ASM_DOMAIN_FANOUT_WORKERS="${ASM_DOMAIN_FANOUT_WORKERS:-3}"
  export ASM_GATE_DEFAULT="${ASM_GATE_DEFAULT:-3}"
  export ASM_GATE_SUBFINDER="${ASM_GATE_SUBFINDER:-3}"
  export ASM_GATE_ASSETFINDER="${ASM_GATE_ASSETFINDER:-3}"
  export ASM_GATE_HTTPX="${ASM_GATE_HTTPX:-3}"
  export ASM_GATE_AMASS="${ASM_GATE_AMASS:-1}"
  export ASM_GATE_NUCLEI="${ASM_GATE_NUCLEI:-1}"
  export ASM_GATE_NAABU="${ASM_GATE_NAABU:-1}"
  export ASM_GATE_GOWITNESS="${ASM_GATE_GOWITNESS:-1}"
  export ASM_GATE_WPSCAN="${ASM_GATE_WPSCAN:-1}"
  export ASM_GATE_FFUF="${ASM_GATE_FFUF:-1}"
  export ASM_WATCHDOG_MAX_LOAD="${ASM_WATCHDOG_MAX_LOAD:-4}"
  export ASM_WATCHDOG_MIN_MEM_MB="${ASM_WATCHDOG_MIN_MEM_MB:-1536}"
  export ASM_WATCHDOG_MAX_RECON_PROCS="${ASM_WATCHDOG_MAX_RECON_PROCS:-10}"
fi

echo "[*] Reiniciando ASM Platform em http://$HOST:$PORT (workers=$ASM_JOB_WORKERS, global_procs=$ASM_GLOBAL_PROC_LIMIT, fanout=$ASM_DOMAIN_FANOUT_WORKERS)"

if [[ -f "$PID_FILE" ]]; then
  OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ -n "${OLD_PID:-}" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[*] Encerrando PID antigo: $OLD_PID"
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PID_FILE"
fi

for PID in $(pgrep -f "python3 .*server.py.*--port $PORT" || true); do
  if kill -0 "$PID" 2>/dev/null; then
    echo "[*] Encerrando processo na porta alvo: $PID"
    kill "$PID" 2>/dev/null || true
  fi
done

if command -v lsof >/dev/null 2>&1; then
  for PID in $(lsof -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true); do
    if kill -0 "$PID" 2>/dev/null; then
      echo "[*] Encerrando listener na porta $PORT: $PID"
      kill "$PID" 2>/dev/null || true
    fi
  done
fi

sleep 2

nohup python3 server.py --host "$HOST" --port "$PORT" >> "$LOG_FILE" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$PID_FILE"

sleep 2

if kill -0 "$NEW_PID" 2>/dev/null; then
  echo "[+] Servidor iniciado com PID $NEW_PID"
  echo "[+] Log: $LOG_FILE"
else
  echo "[!] Falha ao iniciar o servidor. Verifique: $LOG_FILE" >&2
  tail -n 30 "$LOG_FILE" >&2 || true
  exit 1
fi
