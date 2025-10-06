#!/usr/bin/env bash
set -euo pipefail  # safe defaults

if [ $# -lt 1 ]; then
  echo "Error: Missing argument!" >&2
  echo "Usage: $0 <arg>" >&2
  exit 1
fi

./build/qjs_new $1
echo $?