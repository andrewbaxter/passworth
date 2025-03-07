#!/usr/bin/env bash
nix-build makeBrowserZip.nix -o ./ext_firefox.zip --arg debug false
