# Hack?
#
# Due to gtk dependencies `native` ends up depending on systemd (via udev?). So if you want to override the systemd package to inject
# calls to e.g. passworth-tag, it leads to infinite recursion (systemd depending on systemd).
#
# So I split that binary out into a dependency-reduced module that can be included in the overlay without causing recursion.
{ config, pkgs, lib, ... }:
let
  rust = import ../rust.nix { pkgs = pkgs; lib = lib; };
  workspace = rust.stageWorkspace "passworth-native-no-systemd" [
    ./Cargo.toml
    ../../native-no-systemd/Cargo.lock
    ../../native-no-systemd
    ../../shared
    ../../shared-native
  ];
in
{
  config = {
    nixpkgs.overlays = [
      (finalPkgs: prevPkgs: {
        # Can't use naersk, closes on remarshal which pulls in the kitchen sink which includes systemd
        passworthNoSystemd = rust.naersk.buildPackage {
          src = workspace;
          release = false;
        };
      })
    ];
  };
}

