{ pkgs, lib, ... }:
let
  rust = import ../rust.nix { pkgs = pkgs; lib = lib; };
  workspace = rust.stageWorkspace "passworth-native" [
    ./Cargo.toml
    ../../native/Cargo.lock
    ../../native
    ../../shared
    ../../shared-native
  ];
in
{
  config = {
    nixpkgs.overlays = [
      (finalPkgs: prevPkgs: rec {
        passworth = rust.naersk.buildPackage {
          pname = "passworth-native";
          src = workspace;
          release = false;
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.cargo
            pkgs.rustc
            pkgs.rustPlatform.bindgenHook
            pkgs.llvmPackages.libclang
            pkgs.makeWrapper
            pkgs.installShellFiles
          ];
          buildInputs = [
            pkgs.at-spi2-atk
            pkgs.atkmm
            pkgs.cairo
            pkgs.gdk-pixbuf
            pkgs.glib
            pkgs.gtk4
            pkgs.harfbuzz
            pkgs.librsvg
            pkgs.libsoup_3
            pkgs.pango
            pkgs.nettle
            pkgs.pcsclite
            pkgs.openssl
          ];
          postInstall =
            let
              libs = [ pkgs.openssl pkgs.nettle pkgs.gmp pkgs.bzip2 pkgs.pcsclite pkgs.gtk4 pkgs.pango pkgs.glib ];
            in
            ''
              rm $out/bin/generate_jsonschema
              wrapProgram $out/bin/passworth-server --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath libs}
              wrapProgram $out/bin/passworth --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath libs}
              (cd $out/bin; ln -s passworth pw)
              installShellCompletion --cmd pw --bash ${./complete_pw.bash} --zsh ${./complete_pw.zsh}
              installShellCompletion --cmd passworth --bash ${./complete_pw.bash} --zsh ${./complete_pw.zsh}
            '';
        };
      })
    ];
  };
}

