#!/usr/bin/env bash
# Model-check docs/tla/DeliveryService.tla under each configuration with TLC.
# Needs a JRE and tla2tools.jar under $MLS_WORK (see scripts/fetch-tools.sh).
set -uo pipefail
source "$(dirname "$0")/env.sh"
cd "$(dirname "$0")/../docs/tla"
JAVA="$MLS_WORK/jre/bin/java"
JAR="$MLS_WORK/tla/tla2tools.jar"
for cfg in fenced fenced_2x2 fenced_logorder unfenced_logorder unfenced_mergeonack relay unfenced_logorder_nofork unfenced_mergeonack_nofork relay_nofork; do
  echo "== $cfg"
  "$JAVA" -XX:+UseParallelGC -Xmx1g -cp "$JAR" tlc2.TLC -workers 2 -deadlock -metadir "$MLS_WORK/tla/states" \
      -config "$cfg.cfg" DeliveryService.tla > "$MLS_WORK/tla/$cfg.out" 2>&1
  grep -E "Model checking completed|Invariant .* is violated|distinct states found" "$MLS_WORK/tla/$cfg.out" | tail -2
done
