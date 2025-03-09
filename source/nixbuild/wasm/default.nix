{ pkgs, lib, debug }:
let
  rust = import ../rust.nix { pkgs = pkgs; lib = lib; };
  workspace = rust.stageWorkspace "passworth-wasm" [
    ./Cargo.toml
    ../../wasm/Cargo.lock
    ../../wasm/.cargo
    ../../wasm
    ../../shared
  ];
in
rust.naersk.buildPackage {
  src = workspace;
  release = false;
  CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
}

