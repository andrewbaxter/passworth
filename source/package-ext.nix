let
  pkgs = import <nixpkgs> { };
  lib = import (<nixpkgs> + "/lib");
  passworth = import ./default.nix { pkgs = pkgs; lib = lib; };
in
derivation {
  name = "passworth-firefox.zip";
  system = builtins.currentSystem;
  builder = "${pkgs.bash}/bin/bash";
  args = [
    (pkgs.writeText "passworth-ext-packed-firefox-builder" ''
      cd ${passworth.extensionUnpacked}/browser_firefox
      ${pkgs.zip}/bin/zip $out --recurse-paths *
    '')
  ];
}
