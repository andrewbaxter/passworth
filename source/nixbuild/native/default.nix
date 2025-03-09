{ pkgs, lib, ... }:
let
  package = import ./package.nix { pkgs = pkgs; lib = lib; };
in
{
  config = {
    nixpkgs.overlays = [
      (finalPkgs: prevPkgs: rec {
        passworth = import ./package.nix { pkgs = prevPkgs; lib = lib; };
      })
    ];
  };
}

