#!/bin/bash
set -euo pipefail

# CCC 2.x provisioning is shared by source builds and release packaging.
# buildExtension already depends on prepareStdump; this wrapper is optional.
cd "$(dirname "$0")/.."
if [[ -z "$GHIDRA_INSTALL_DIR" ]]; then
  echo "Set GHIDRA_INSTALL_DIR to provision CCC 2.x using Gradle" >&2
  exit 1
fi
gradle "-PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR" prepareStdump
