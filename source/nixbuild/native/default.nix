{ pkgs, lib, ... }:
{
  config = {
    nixpkgs.overlays = [
      (finalPkgs: prevPkgs: rec {
        passworth = import ./package.nix {
          pkgs = prevPkgs;
          lib = lib;
        };
      })
    ];
  };
}
