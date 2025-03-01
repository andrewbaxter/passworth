let
  pkgs = import <nixpkgs> { };
  lib = import (<nixpkgs> + "/lib");
  passworth = import ./default.nix { pkgs = pkgs; lib = lib; };
in
pkgs.mkShell {
  name = "passworth-browser-test";
  packages = [
    passworth.package
  ];
  nativeBuildInputs = [ ];
  buildInputs = [ ];
}
