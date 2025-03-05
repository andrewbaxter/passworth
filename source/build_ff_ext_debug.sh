#!/usr/bin/env bash
nix-build package-ext.nix -o ./ext_firefox_debug.zip --arg debug true
