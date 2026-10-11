#!/bin/sh
set -eu

bin=${VSU_BIN:?set VSU_BIN to the agent binary}
certs=${CERT_DIR:?set CERT_DIR to the output of gen-certs.sh}
vault_bin=${VAULT_BIN:-vault}
work=$(mktemp -d)
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_CACERT="$certs/ca.pem"
unset VAULT_TOKEN
pids=""

cleanup() {
  for p in $pids; do kill "$p" 2>/dev/null || true; done
  [ -n "${vault_pid:-}" ] && kill "$vault_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

fail() {
  echo "FAIL: $*" >&2
  for f in "$work"/*.log; do
    [ -f "$f" ] || continue
    echo "--- $f" >&2
    sed 's/^/  /' "$f" >&2
  done
  exit 1
}

sealed() {
  "$vault_bin" status -format=json 2>/dev/null | grep -q '"sealed": true'
}

progress() {
  "$vault_bin" status -format=json 2>/dev/null | sed -n 's/.*"progress": \([0-9]*\).*/\1/p'
}

wait_unsealed() {
  i=0
  while sealed; do
    i=$((i + 1))
    [ "$i" -le "$1" ] || return 1
    sleep 1
  done
}

agent_config() {
  cfg=$1
  shift
  {
    echo "interval_secs = 1"
    echo "extra_ca_file = \"$certs/ca.pem\""
    for name in "$@"; do
      printf '[[endpoint]]\nname = "%s"\naddr = "127.0.0.1:8200"\n' "$name"
    done
  } > "$work/$cfg.toml"
}

start_agent() {
  id=$1
  share=$2
  shift 2
  mkdir -p "$work/cred-$id"
  printf '%s\n' "$share" > "$work/cred-$id/vault-unseal-share"
  agent_config "$id" "$@"
  CREDENTIALS_DIRECTORY="$work/cred-$id" "$bin" "$work/$id.toml" >> "$work/$id.log" 2>&1 &
  pids="$pids $!"
}

stop_agents() {
  for p in $pids; do kill "$p" 2>/dev/null || true; done
  for p in $pids; do wait "$p" 2>/dev/null || true; done
  pids=""
}

mkdir -p "$work/data"
cat > "$work/vault.hcl" <<EOF
storage "file" {
  path = "$work/data"
}
listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_cert_file = "$certs/tls.pem"
  tls_key_file  = "$certs/tls.key"
}
disable_mlock = true
api_addr      = "https://127.0.0.1:8200"
EOF
"$vault_bin" server -config="$work/vault.hcl" > "$work/vault-server.log" 2>&1 &
vault_pid=$!

i=0
until "$vault_bin" status > /dev/null 2>&1 || [ $? -eq 2 ]; do
  i=$((i + 1))
  [ "$i" -le 30 ] || fail "vault server did not start"
  sleep 1
done

"$vault_bin" operator init -key-shares=8 -key-threshold=3 > "$work/init.txt"
key() { sed -n "s/^Unseal Key $1: //p" "$work/init.txt"; }
root=$(sed -n 's/^Initial Root Token: //p' "$work/init.txt")
for n in 6 7 8; do "$vault_bin" operator unseal "$(key "$n")" > /dev/null; done
sealed && fail "manual unseal failed"
VAULT_TOKEN=$root "$vault_bin" operator seal > /dev/null
sealed || fail "vault did not seal"
echo "ok: initialized 8/3 and sealed"

for case in missing empty; do
  mkdir -p "$work/cred-$case"
  [ "$case" = empty ] && : > "$work/cred-$case/vault-unseal-share"
  agent_config "$case" vault-0.test
  if CREDENTIALS_DIRECTORY="$work/cred-$case" timeout 10 "$bin" "$work/$case.toml" > "$work/$case.log" 2>&1; then
    fail "agent exited 0 with $case credential"
  fi
  rc=0
  CREDENTIALS_DIRECTORY="$work/cred-$case" timeout 10 "$bin" "$work/$case.toml" > /dev/null 2>&1 || rc=$?
  [ "$rc" -ne 124 ] || fail "agent kept running with $case credential"
  echo "ok: $case credential exits $rc"
done

start_agent wrong-san "$(key 4)" wrong.test
sleep 8
sealed || fail "vault unsealed through wrong-SAN endpoint"
[ "$(progress)" = 0 ] || fail "wrong-SAN agent sent its share (progress $(progress))"
grep -qi "certificate" "$work/wrong-san.log" || fail "wrong-SAN agent did not report a certificate error"
stop_agents
echo "ok: wrong-SAN agent did not send its share"

start_agent a1 "$(key 1)" vault-0.test vault-1.test vault-2.test
start_agent a2 "$(key 2)" vault-1.test vault-2.test vault-0.test
start_agent a3 "$(key 3)" vault-2.test vault-0.test vault-1.test
wait_unsealed 30 || fail "3 agents did not unseal vault within 30s"
echo "ok: 3 agents unsealed vault"

stop_agents
VAULT_TOKEN=$root "$vault_bin" operator seal > /dev/null
sealed || fail "vault did not seal again"
fake=$(head -c 33 /dev/urandom | base64)
"$vault_bin" operator unseal "$fake" > /dev/null
[ "$(progress)" = 1 ] || fail "stale share did not set progress 1"
start_agent a1 "$(key 1)" vault-0.test
start_agent a2 "$(key 2)" vault-1.test
start_agent a3 "$(key 3)" vault-2.test
wait_unsealed 30 || fail "agents stuck behind a stale share"
grep -q "unseal rejected" "$work"/a[123].log || fail "no agent reported the rejected unseal"
echo "ok: agents recovered from a stale share"
stop_agents

for n in 1 2 3 4; do
  if grep -rqF "$(key "$n")" "$work"/*.log; then
    fail "share $n appears in a log"
  fi
done
echo "ok: no share in agent logs"
for f in wrong-san a1 a2 a3; do
  echo "--- $f.log"
  sed 's/^/  /' "$work/$f.log"
done
echo "PASS"
