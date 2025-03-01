#!/usr/bin/env bash
set -xeu
rm -f generated/jsonschema/*.json
cargo run --bin generate_jsonschema