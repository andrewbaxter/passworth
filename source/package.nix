{ pkgs, lib }:
let
  fenix = import (fetchTarball "https://github.com/nix-community/fenix/archive/1a79901b0e37ca189944e24d9601c8426675de50.zip") { };
  naersk = pkgs.callPackage (fetchTarball "https://github.com/nix-community/naersk/archive/378614f37a6bee5a3f2ef4f825a73d948d3ae921.zip") (
    let
      toolchain = fenix.combine [
        fenix.latest.rustc
        fenix.latest.cargo
      ];
    in
    {
      rustc = toolchain;
      cargo = toolchain;
    }
  );
in
naersk.buildPackage {
  root = ./.;
  nativeBuildInputs = [
    pkgs.pkg-config
    pkgs.cargo
    pkgs.rustc
    pkgs.rustPlatform.bindgenHook
    pkgs.llvmPackages.libclang
    pkgs.makeWrapper
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
  postInstall = let 
    libs = [ pkgs.openssl pkgs.nettle pkgs.gmp pkgs.bzip2 pkgs.pcsclite pkgs.gtk4 pkgs.pango pkgs.glib ];
  in ''
    wrapProgram $out/bin/passworth-server --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath libs}
    wrapProgram $out/bin/passworth --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath libs}
    rm $out/bin/generate_jsonschema
  '';
}
