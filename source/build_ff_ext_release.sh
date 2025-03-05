#!/usr/bin/env bash
nix-build package-ext.nix -o ./ext_firefox.zip --arg debug false
