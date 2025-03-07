{ pkgs, lib }: rec {
  fenix = import (fetchTarball "https://github.com/nix-community/fenix/archive/1a79901b0e37ca189944e24d9601c8426675de50.zip") { };
  toolchain = fenix.combine [
    fenix.latest.rustc
    fenix.latest.cargo
    fenix.targets.wasm32-unknown-unknown.latest.rust-std
  ];
  platform = pkgs.makeRustPlatform {
    cargo = toolchain;
    rustc = toolchain;
  };
  crane = pkgs.callPackage (fetchTarball "https://github.com/ipetkov/crane/archive/75390a36cd0c2cdd5f1aafd8a9f827d7107f2e53.zip") {
    rustc = toolchain;
    cargo = toolchain;
  };
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
    derivation {
      name = "stage-rust-workspace-${name}";
      system = builtins.currentSystem;
      builder = "${pkgs.bash}/bin/bash";
      args = [
        (pkgs.writeText "stage-rust-workspace-${name}-builder" ''
          set -xeu -o pipefail
          ${pkgs.coreutils}/bin/mkdir $out
          cd $out
          ${linkLines}
        '')
      ];
    };
}
