#!/bin/bash
set -euo pipefail

if [ -z "${1+set}" ];  then
  echo "usage: ./scripts/add_migration.sh name_of_migration"
  exit 1
fi

DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT="$( dirname "$DIR" )"

ATLAS_DIR="$(mktemp --directory --tmpdir logseq-sync-atlas-XXXXX)"

echo "Creating migration db/sqlite/migrations/$1.sql"

atlas migrate diff "$1" \
  --dir "file://db/sqlite/migrations" \
  --to "file://db/sqlite/schema.sql" \
  --dev-url "sqlite://${ATLAS_DIR}/logseq-sync.db"

rm -rf "$ATLAS_DIR"
