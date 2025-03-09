{ debug }:
let
  pkgs = import <nixpkgs> { };
  lib = import (<nixpkgs> + "/lib");
  native = import ./nixbuild/native/package.nix { pkgs = pkgs; lib = lib; };
  browser = import ./browser.nix {
    pkgs = pkgs // {
      passworth = native;
    };
    lib = lib;
    debug = debug;
  };
in
derivation {
  name = "passworth-firefox.zip";
  system = builtins.currentSystem;
  builder = "${pkgs.bash}/bin/bash";
  args = [
    (pkgs.writeText "passworth-ext-packed-firefox-builder" ''
      cd ${browser.extensionUnpacked}/browser_firefox
      ${pkgs.zip}/bin/zip $out --recurse-paths *
    '')
  ];
}
