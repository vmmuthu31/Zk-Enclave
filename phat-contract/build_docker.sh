#!/bin/bash
set -e

docker build -t zkenclave-builder .

docker run --rm -v "$(pwd):/code" zkenclave-builder

echo "Build complete! Artifacts are in target/ink/"
