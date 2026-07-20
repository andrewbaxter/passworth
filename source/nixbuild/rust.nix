{ pkgs, lib }: rec {
  fenix = import (fetchTarball "https://github.com/nix-community/fenix/archive/480c95c3c9ca478e857f7153639010fb54ec73e8.zip") { };
  toolchain = fenix.combine [
    fenix.latest.rustc
    fenix.latest.cargo
    fenix.targets.wasm32-unknown-unknown.latest.rust-std
  ];
  naersk = pkgs.callPackage (fetchTarball "https://github.com/nix-community/naersk/archive/378614f37a6bee5a3f2ef4f825a73d948d3ae921.zip") {
    rustc = toolchain;
    cargo = toolchain;
  };
  stageWorkspace = name: files:
    let
      linkLines = lib.strings.concatStringsSep "\n" (map
        (f: ''
          filename=$(${pkgs.coreutils}/bin/basename ${f} | ${pkgs.gnused}/bin/sed -e 's/[^-]*-//')
          ${pkgs.coreutils}/bin/cp -r ${f} $filename
        '')
        files);
    in
    pkgs.runCommand "stage-rust-workspace-${name}" { } ''
      set -xeu -o pipefail
      ${pkgs.coreutils}/bin/mkdir $out
      cd $out
      ${linkLines}
    '';
}
