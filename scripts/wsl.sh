#!/usr/bin/env bash
# Run a command inside WSL with the project environment. Usage from Windows:
#   wsl -d Ubuntu-24.04 --exec bash /mnt/c/Mac/Documents/MLSChat/scripts/wsl.sh <cmd...>
source "$(dirname "$0")/env.sh"
cd "$(dirname "$0")/.."
exec "$@"
