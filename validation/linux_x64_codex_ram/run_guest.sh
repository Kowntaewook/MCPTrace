#!/bin/sh
set -eu

# Run inside the isolated Ubuntu guest, after installing the pinned Codex CLI
# binary and the official MCP SDK fixture in /home/ubuntu/experiment.
run_dir="$1"
marker="$2"
experiment=/home/ubuntu/experiment
codex_home="$experiment/codex-home"
node="$experiment/../node-v22.23.4-linux-x64/bin/node"

mkdir -p "$run_dir" "$codex_home"
CODEX_HOME="$codex_home" "$experiment/codex-linux-x64" mcp remove mcptrace_codex >/dev/null 2>&1 || true
CODEX_HOME="$codex_home" "$experiment/codex-linux-x64" mcp remove mcptrace_probe >/dev/null 2>&1 || true
CODEX_HOME="$codex_home" "$experiment/codex-linux-x64" mcp add mcptrace_probe -- \
  "$node" "$experiment/validation/real_host/stdio_proxy.mjs" \
  "$run_dir/traffic.jsonl" "$experiment/validation/cross_runtime/stdio_server.mjs" \
  > "$run_dir/mcp-config.log"

nohup python3 "$experiment/model_fixture.py" --run-dir "$run_dir" \
  --marker "$marker" > "$run_dir/model.log" 2>&1 < /dev/null &
model_pid=$!
printf '%s\n' "$model_pid" > "$run_dir/model.pid"
sleep 1
kill -0 "$model_pid"

nohup env CODEX_HOME="$codex_home" "$experiment/codex-linux-x64" exec \
  --ephemeral --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox \
  -C "$experiment" -c model_provider=fixture \
  -c mcp_optional_startup_grace_ms=0 \
  -c 'model_providers.fixture={name="Fixture",base_url="http://127.0.0.1:18765/v1",wire_api="responses"}' \
  -c features.plugins=false -m fixture-model \
  "Use mcptrace_probe echo_marker with marker $marker." \
  > "$run_dir/codex.log" 2>&1 < /dev/null &
client_pid=$!
printf '{"pid":%s}\n' "$client_pid" > "$run_dir/client-ready.json"
printf '%s\n' "$client_pid"
