#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "Using build context: $SCRIPT_DIR"

docker build -t zkenclave-builder .

docker run --rm -v "$(pwd):/code" zkenclave-builder

echo "Build complete! Artifacts function output are in target/ink/"
