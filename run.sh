#!/bin/sh
# Запуск из исходного каталога без установки.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -P -m shkatulka "$@"
