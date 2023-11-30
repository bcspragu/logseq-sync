#!/bin/bash
set -euo pipefail

DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT="$( dirname "$DIR" )"

atlas migrate apply \
  --dir "file://db/sqlite/migrations" \
  --url "sqlite://logseq-sync.db"
