# Stages the cargo workspace (../Cargo.toml, ../Cargo.lock and all member crates) plus
# the sibling glove checkout that the workspace's `[patch.crates-io]` entry points at
# (`../../glove`, so it must sit next to the `passworth` directory) into a single
# derivation. Packages are then built from `${workspace}/passworth` with `cargo -p`.
#
# naersk copies patched path sources itself and can't handle paths outside the
# workspace root, so glove is staged inside the workspace and the patch path rewritten
# to match (the lockfile doesn't record path dependency locations, so it stays valid).
{ pkgs, lib }:
let
  copy = src: dest: ''
    ${pkgs.coreutils}/bin/cp -r --no-preserve=all ${src} ${dest}
  '';
in
pkgs.runCommand "passworth-workspace" { } ''
  set -eu
  ${pkgs.coreutils}/bin/mkdir -p $out/passworth
  ${copy ../Cargo.toml "$out/passworth/Cargo.toml"}
  ${copy ../Cargo.lock "$out/passworth/Cargo.lock"}
  ${copy ../rust-toolchain.toml "$out/passworth/rust-toolchain.toml"}
  ${copy (lib.cleanSource ../native) "$out/passworth/native"}
  ${copy (lib.cleanSource ../native-ui) "$out/passworth/native-ui"}
  ${copy (lib.cleanSource ../native-no-systemd) "$out/passworth/native-no-systemd"}
  ${copy (lib.cleanSource ../shared) "$out/passworth/shared"}
  ${copy (lib.cleanSource ../shared-native) "$out/passworth/shared-native"}
  ${copy (lib.cleanSource ../../../glove) "$out/passworth/glove"}
  ${pkgs.gnused}/bin/sed -i 's|^glove = { path = "../../glove" }$|glove = { path = "glove" }|' $out/passworth/Cargo.toml
  ${pkgs.gnugrep}/bin/grep -q 'path = "glove"' $out/passworth/Cargo.toml
''
