#!/usr/bin/env bash
# Own the local development vault, CLI bridge and Vite. Stop retains the vault's
# persistent data and never touches production tunnels or shared infrastructure.
set -euo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
state_dir="$repo_dir/.tools/ui-dev"
vite_script="$repo_dir/ui/node_modules/vite/bin/vite.js"
bridge_bin="$repo_dir/.tools/hashvault-dev"
vault_bin="$repo_dir/.tools/hashvault-local"
vault_dir="$repo_dir/.tools/dev-vault"
action=${1:?start or stop required}
port=${2:?port required}
bridge_port=${3:-8822}
for selected_port in "$port" "$bridge_port"; do
  case "$selected_port" in ''|*[!0-9]*) exit 2 ;; esac
  [[ "$selected_port" -gt 0 && "$selected_port" -le 65535 ]] || exit 2
done
[[ "$port" != "$bridge_port" ]] || exit 2
C_OK=${C_OK:-} C_WARN=${C_WARN:-} C_ERR=${C_ERR:-} C_RESET=${C_RESET:-}

owns_process() {
  local actual_start actual_command
  actual_start=$(LC_ALL=C ps -p "$pid" -o lstart= 2>/dev/null) || return 1
  if [[ "$actual_start" != "$started" ]]; then
    # Accept state written by the previous launcher in the operator's locale.
    actual_start=$(ps -p "$pid" -o lstart= 2>/dev/null) || return 1
  fi
  [[ "$actual_start" == "$started" ]] || return 1
  actual_command=$(ps -p "$pid" -o args= 2>/dev/null) || return 1
  case "$kind" in
    vite) [[ "$actual_command" == *"$vite_script"*"--port $port --strictPort"* ]] ;;
    bridge) [[ "$actual_command" == *"$bridge_bin ui --listen 127.0.0.1:$bridge_port"* ]] ;;
    vault) [[ "$actual_command" == *"$vault_bin --state $vault_dir --bao "* ]] ;;
  esac
}

record_child() {
  started=$(LC_ALL=C ps -p "$pid" -o lstart=) || return 1
  printf '%s\n%s\n' "$pid" "$started" > "$state_dir/$record"
}

case "$action" in
  start)
    [[ -x "$bridge_bin" ]] || { printf '%b[make] pont CLI absent : utiliser make dev%b\n' "$C_ERR" "$C_RESET" >&2; exit 1; }
    [[ -x "$vault_bin" && -x "${HASHVAULT_BAO_BIN:-}" ]] || { printf '%b[make] coffre local absent : utiliser make dev%b\n' "$C_ERR" "$C_RESET" >&2; exit 1; }
    command -v lsof >/dev/null || { printf '%b[make] lsof est requis pour suivre le pont API%b\n' "$C_ERR" "$C_RESET" >&2; exit 1; }
    for selected_port in "$port" "$bridge_port"; do
      if lsof -nP -iTCP:"$selected_port" -sTCP:LISTEN >/dev/null 2>&1; then
        printf '%b[make] port %s déjà occupé ; aucun processus existant arrêté%b\n' "$C_ERR" "$selected_port" "$C_RESET" >&2
        exit 1
      fi
    done
    mkdir -p "$repo_dir/.tools"
    if ! mkdir "$state_dir" 2>/dev/null; then
      printf '%b[make] serveur déjà suivi : utiliser make stop avant make dev%b\n' "$C_ERR" "$C_RESET" >&2
      exit 1
    fi
    owner="$$:$RANDOM"
    printf '%s\n' "$owner" > "$state_dir/owner"
    vite_pid= bridge_pid= vault_pid=
    cleanup() {
      for child in "$vite_pid" "$bridge_pid" "$vault_pid"; do
        [[ -n "$child" ]] || continue
        pid=$child
        kind=vite record=pid
        if [[ "$child" == "$bridge_pid" ]]; then kind=bridge record=bridge-pid; fi
        if [[ "$child" == "$vault_pid" ]]; then kind=vault record=vault-pid; fi
        started=
        if [[ -f "$state_dir/$record" ]]; then
          { IFS= read -r pid; IFS= read -r started; } < "$state_dir/$record" || true
        fi
        if [[ "$pid" == "$child" ]] && { [[ -z "$started" ]] || owns_process; }; then
          kill -TERM "$child" 2>/dev/null || true
        fi
        wait "$child" 2>/dev/null || true
      done
      if [[ -f "$state_dir/owner" && "$(cat "$state_dir/owner")" == "$owner" ]]; then
        rm -f "$state_dir/pid" "$state_dir/bridge-pid" "$state_dir/vault-pid" "$state_dir/owner"
        rmdir "$state_dir" 2>/dev/null || true
      fi
    }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    "$vault_bin" --state "$vault_dir" --bao "$HASHVAULT_BAO_BIN" &
    vault_pid=$!; pid=$vault_pid; record=vault-pid
    record_child
    ready=false
    for ((attempt = 0; attempt < 600; attempt++)); do
      kill -0 "$vault_pid" 2>/dev/null || break
      if [[ -f "$vault_dir/ready" && "$(cat "$vault_dir/ready" 2>/dev/null || true)" == "$vault_pid" && -S "$vault_dir/api.sock" && -s "$vault_dir/token" ]]; then ready=true; break; fi
      sleep 0.1
    done
    if [[ "$ready" != true ]]; then
      printf '%b[make] le coffre local ne démarre pas ; ses données sont conservées%b\n' "$C_ERR" "$C_RESET" >&2
      exit 1
    fi
    export HASHVAULT_SOCKET="$vault_dir/api.sock" HASHVAULT_TOKEN_FILE="$vault_dir/token"
    "$bridge_bin" ui --listen "127.0.0.1:$bridge_port" --assets "$repo_dir/ui" --browser-origin "http://127.0.0.1:$port" --dev-session &
    bridge_pid=$!; pid=$bridge_pid; record=bridge-pid
    record_child
    ready=false
    for ((attempt = 0; attempt < 80; attempt++)); do
      kill -0 "$bridge_pid" 2>/dev/null || break
      if lsof -nP -a -p "$bridge_pid" -iTCP:"$bridge_port" -sTCP:LISTEN >/dev/null 2>&1; then ready=true; break; fi
      sleep 0.1
    done
    if [[ "$ready" != true ]]; then
      printf '%b[make] le pont API ne démarre pas sur le port %s%b\n' "$C_ERR" "$bridge_port" "$C_RESET" >&2
      exit 1
    fi
    cd "$repo_dir/ui"
    "${BUN:-bun}" --bun "$vite_script" --host 127.0.0.1 --port "$port" --strictPort &
    vite_pid=$!; pid=$vite_pid; record=pid
    record_child
    printf '%b[make] interface sur http://127.0.0.1:%s/ (Ctrl+C ou make stop)%b\n' "$C_OK" "$port" "$C_RESET"
    # A stopped child ends the whole owned development stack.
    while kill -0 "$vite_pid" 2>/dev/null && kill -0 "$bridge_pid" 2>/dev/null && kill -0 "$vault_pid" 2>/dev/null; do sleep 0.2; done
    result=0
    if ! kill -0 "$vite_pid" 2>/dev/null; then wait "$vite_pid" || result=$?; elif ! kill -0 "$bridge_pid" 2>/dev/null; then wait "$bridge_pid" || result=$?; else wait "$vault_pid" || result=$?; fi
    case "$result" in 130|143) exit 0 ;; *) exit "$result" ;; esac
    ;;
  stop)
    if [[ ! -d "$state_dir" ]]; then
      printf '%b[make] aucun serveur de développement suivi pour ce dépôt%b\n' "$C_WARN" "$C_RESET"
      exit 0
    fi
    if [[ ! -f "$state_dir/pid" && ! -f "$state_dir/bridge-pid" && ! -f "$state_dir/vault-pid" ]]; then
      printf '%b[make] démarrage en cours : réessayer après le démarrage%b\n' "$C_WARN" "$C_RESET" >&2
      exit 1
    fi
    observed_owner=$(cat "$state_dir/owner" 2>/dev/null || true)
    for record in pid bridge-pid vault-pid; do
      [[ -f "$state_dir/$record" ]] || continue
      kind=vite
      case "$record" in bridge-pid) kind=bridge ;; vault-pid) kind=vault ;; esac
      # The foreground parent can remove this file after the previous signal.
      { IFS= read -r pid; IFS= read -r started; } 2>/dev/null < "$state_dir/$record" || continue
      case "$pid" in ''|*[!0-9]*) exit 1 ;; esac
      if owns_process; then
        kill -TERM "$pid" 2>/dev/null || true
        stop_attempts=80
        [[ "$kind" != vault ]] || stop_attempts=200
        for ((attempt = 0; attempt < stop_attempts; attempt++)); do
          owns_process || break
          sleep 0.1
        done
        if owns_process; then
          printf '%b[make] le processus %s ne termine pas après SIGTERM%b\n' "$C_ERR" "$kind" "$C_RESET" >&2
          exit 1
        fi
      fi
    done
    # Never delete a new launch's state while the old foreground parent exits.
    if [[ -d "$state_dir" && "$(cat "$state_dir/owner" 2>/dev/null || true)" == "$observed_owner" ]]; then
      rm -f "$state_dir/pid" "$state_dir/bridge-pid" "$state_dir/vault-pid" "$state_dir/owner"
      rmdir "$state_dir" 2>/dev/null || true
    fi
    printf '%b[make] processus de développement arrêtés ; secrets locaux conservés%b\n' "$C_OK" "$C_RESET"
    ;;
  *) printf 'usage: ui-dev.sh start|stop PORT [BRIDGE_PORT]\n' >&2; exit 2 ;;
esac
