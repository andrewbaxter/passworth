#!/usr/bin/bash -xeu
rm -f generated/jsonschema/*.json
cargo run --bin generate_jsonschema