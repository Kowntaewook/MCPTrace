#!/bin/bash
set -euo pipefail

# Run one independent, synthetic client exchange in the isolated Linux VM.
# Usage: guest_case.sh start CASE RUN_ID MARKER PORT | stop CASE RUN_ID
action=${1:?action}
case_name=${2:?case}
run_id=${3:?run_id}
marker=${4:-}
port=${5:-}
experiment=/home/ubuntu/experiment
run_dir="$experiment/repeat/$run_id"
node=/home/ubuntu/node-v22.23.4-linux-x64/bin/node
mcpdo_bin=/home/ubuntu/inspector/node_modules/.bin/mcpdo
codex="$experiment/codex-linux-x64"
export PATH="/home/ubuntu/node-v22.23.4-linux-x64/bin:$PATH"
export MCP_INSPECTOR_DAEMON_DIR="$run_dir/daemon"
export MCP_STORAGE_DIR="$run_dir/storage"
export MCP_CATALOG_PATH="$run_dir/catalog.json"
export MCP_INSPECTOR_SECRET_STORE=memory

mcpdo_cli() { "$mcpdo_bin" "$@"; }

wait_file() {
  local target=$1
  for attempt in $(seq 1 180); do
    if [ -s "$target" ]; then return 0; fi
    sleep 1
  done
  printf 'Timed out waiting for %s\n' "$target" >&2
  return 1
}

start_inspector() {
  if [ "$case_name" = inspector-http ]; then
    nohup "$node" "$experiment/validation/cross_runtime/node_fixture.mjs" \
      server "$run_dir" "$port" > "$run_dir/server.log" 2>&1 < /dev/null &
    printf '%s\n' "$!" > "$run_dir/server.pid"
    wait_file "$run_dir/server-ready.json"
    mcpdo_cli --format json connect --transport http --era legacy \
      "http://127.0.0.1:$port/mcp" > "$run_dir/connect.json"
  else
    mcpdo_cli --format json connect --transport stdio --era legacy \
      "$node" "$experiment/validation/real_host/stdio_proxy.mjs" \
      "$run_dir/traffic.jsonl" \
      "$experiment/validation/cross_runtime/stdio_server.mjs" \
      > "$run_dir/connect.json"
  fi
  local connection
  connection=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' \
    "$run_dir/connect.json")
  mcpdo_cli --format json --connection "$connection" tools/list \
    > "$run_dir/tools-list.json"
  mcpdo_cli --format json --connection "$connection" tools/call \
    echo_marker "marker:=$marker" > "$run_dir/tool-call.json"
  python3 -c 'import json,sys; assert sys.argv[2] in json.dumps(json.load(open(sys.argv[1])))' \
    "$run_dir/tool-call.json" "$marker"
  mcpdo_cli --format json daemon status > "$run_dir/daemon-status.json"
  python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); assert type(x["pid"]) is int; json.dump({"pid":x["pid"]},open(sys.argv[2],"w"))' \
    "$run_dir/daemon-status.json" "$run_dir/client-ready.json"
  touch "$run_dir/event-complete"
}

start_control() {
  local script
  if [ "$case_name" = lsp-control ]; then
    script="$experiment/validation/cross_runtime/lsp_control.mjs"
  else
    script="$experiment/validation/real_host/jsonrpc_control.mjs"
  fi
  nohup "$node" "$script" "$run_dir" > "$run_dir/client.log" 2>&1 < /dev/null &
  printf '%s\n' "$!" > "$run_dir/client.pid"
  wait_file "$run_dir/client-ready.json"
  if [ "$case_name" = lsp-control ]; then
    cp "$run_dir/lsp-traffic.jsonl" "$run_dir/traffic.jsonl"
  fi
  test "$(wc -l < "$run_dir/traffic.jsonl")" -eq 2
  touch "$run_dir/event-complete"
}

start_codex() {
  local home="$run_dir/codex-home"
  mkdir -p "$home"
  CODEX_HOME="$home" "$codex" mcp add mcptrace_probe -- \
    "$node" "$experiment/validation/real_host/stdio_proxy.mjs" \
    "$run_dir/traffic.jsonl" \
    "$experiment/validation/cross_runtime/stdio_server.mjs" \
    > "$run_dir/mcp-config.log"
  nohup python3 "$experiment/model_fixture.py" --run-dir "$run_dir" \
    --marker "$marker" > "$run_dir/model.log" 2>&1 < /dev/null &
  printf '%s\n' "$!" > "$run_dir/model.pid"
  sleep 1
  kill -0 "$(cat "$run_dir/model.pid")"
  nohup env CODEX_HOME="$home" "$codex" exec \
    --ephemeral --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox \
    -C "$experiment" -c model_provider=fixture \
    -c mcp_optional_startup_grace_ms=0 \
    -c 'model_providers.fixture={name="Fixture",base_url="http://127.0.0.1:18765/v1",wire_api="responses"}' \
    -c features.plugins=false -m fixture-model \
    "Use mcptrace_probe echo_marker with marker $marker." \
    > "$run_dir/codex.log" 2>&1 < /dev/null &
  printf '{"pid":%s}\n' "$!" > "$run_dir/client-ready.json"
  wait_file "$run_dir/model-tool-result-observed"
  test "$(wc -l < "$run_dir/traffic.jsonl")" -eq 7
  touch "$run_dir/event-complete"
}

if [ "$action" = start ]; then
  if [ -e "$run_dir" ]; then
    printf 'Run directory already exists: %s\n' "$run_dir" >&2
    exit 1
  fi
  mkdir -p "$run_dir"
  case "$case_name" in
    inspector-http|inspector-stdio) start_inspector ;;
    lsp-control|jsonrpc-control) start_control ;;
    codex-stdio) start_codex ;;
    *) printf 'Unknown case: %s\n' "$case_name" >&2; exit 1 ;;
  esac
  printf 'ready %s %s\n' "$case_name" "$run_id"
elif [ "$action" = stop ]; then
  case "$case_name" in
    inspector-http|inspector-stdio)
      mcpdo_cli daemon stop >/dev/null 2>&1 || true
      if [ -f "$run_dir/server.pid" ]; then kill "$(cat "$run_dir/server.pid")" || true; fi
      ;;
    lsp-control|jsonrpc-control)
      touch "$run_dir/client-stop"
      ;;
    codex-stdio)
      touch "$run_dir/release-model-response"
      sleep 2
      if [ -f "$run_dir/model.pid" ]; then kill "$(cat "$run_dir/model.pid")" || true; fi
      ;;
    *) printf 'Unknown case: %s\n' "$case_name" >&2; exit 1 ;;
  esac
  printf 'stopped %s %s\n' "$case_name" "$run_id"
else
  printf 'Unknown action: %s\n' "$action" >&2
  exit 1
fi
