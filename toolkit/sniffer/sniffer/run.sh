#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "error: $PYTHON not found. Install Python 3.9 or newer." >&2
  exit 1
fi

if [[ "${1:-}" == "--grant-capability" ]]; then
  target="$(readlink -f "$(command -v "$PYTHON")")"
  echo "granting CAP_NET_RAW to $target (asks for your password)"
  sudo setcap cap_net_raw,cap_net_admin=eip "$target"
  echo "done - live capture no longer needs sudo"
  exit 0
fi

if [[ "${1:-}" == "--sample" ]]; then
  "$PYTHON" tools/make_sample_pcap.py sample.pcap
  shift
  exec "$PYTHON" -m netscope -r sample.pcap "${@:---lines}"
fi

if [[ $# -eq 0 ]]; then
  "$PYTHON" -m netscope --help
  exit 0
fi

needs_root=1
for arg in "$@"; do
  case "$arg" in
    -r|--read|-h|--help|--show-rules) needs_root=0 ;;
  esac
done

if [[ $needs_root -eq 1 && $EUID -ne 0 ]]; then
  if "$PYTHON" - <<'PY' 2>/dev/null
import socket, sys
try:
    socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)).close()
except Exception:
    sys.exit(1)
PY
  then
    exec "$PYTHON" -m netscope "$@"
  fi
  echo "raw sockets need elevated privileges - re-running under sudo" >&2
  exec sudo -E "$PYTHON" -m netscope "$@"
fi

exec "$PYTHON" -m netscope "$@"
