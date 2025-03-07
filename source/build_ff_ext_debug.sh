#!/usr/bin/env bash
nix-build makeBrowserZip.nix -o ./ext_firefox_debug.zip --arg debug true
