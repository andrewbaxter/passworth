{ pkgs, lib }:
let
  hoj = import ((fetchTarball "https://github.com/andrewbaxter/hammer-of-json/archive/d018015cd66e9ffff0c4960d0f892853696e9648.zip") + "/package.nix") { };
  fenix = import (fetchTarball "https://github.com/nix-community/fenix/archive/1a79901b0e37ca189944e24d9601c8426675de50.zip") { };
  naersk = pkgs.callPackage (fetchTarball "https://github.com/nix-community/naersk/archive/378614f37a6bee5a3f2ef4f825a73d948d3ae921.zip") (
    let
      toolchain = fenix.combine [
        fenix.latest.rustc
        fenix.latest.cargo
      ];
    in
    {
      rustc = toolchain;
      cargo = toolchain;
    }
  );
  buildRust = { root, extra ? { } }:
    let
      # https://github.com/nix-community/naersk/issues/133
      fixCargoPaths = src:
        let
          cargoToml = lib.importTOML (src + "/Cargo.toml");
          isPathDep = v: (builtins.isAttrs v) && builtins.hasAttr "path" v;
          newCargoToml = cargoToml // {
            dependencies = builtins.mapAttrs
              (n: v:
                if (isPathDep v) && (lib.hasInfix ".." v.path) then
                  v // { path = fixCargoPaths (src + "/${v.path}"); }
                else
                  v
              )
              cargoToml.dependencies;
          };
          newCargoTomlFile = (pkgs.formats.toml { }).generate "Cargo.toml" newCargoToml;
          propagatedBuildInputs = lib.mapAttrsToList
            (n: p: p.path)
            (lib.filterAttrs
              (n: v: (isPathDep v) && (! (lib.isString v.path)))
              newCargoToml.dependencies
            );
        in
        pkgs.runCommand "${lib.last (lib.splitString "/" src)}-fixed-paths"
          { propagatedBuildInputs = propagatedBuildInputs; }
          ''
            cp -r ${src} $out
            chmod +w "$out/Cargo.toml"
            cat < ${newCargoTomlFile} > "$out/Cargo.toml"
          '';
      newRoot = fixCargoPaths root;
    in
    naersk.buildPackage (extra // rec {
      src = newRoot;
      propagatedBuildInputs = newRoot.propagatedBuildInputs;
    });

  native = buildRust {
    root = ./native;
    extra = {
      nativeBuildInputs = [
        pkgs.pkg-config
        pkgs.cargo
        pkgs.rustc
        pkgs.rustPlatform.bindgenHook
        pkgs.llvmPackages.libclang
        pkgs.makeWrapper
      ];
      buildInputs = [
        pkgs.at-spi2-atk
        pkgs.atkmm
        pkgs.cairo
        pkgs.gdk-pixbuf
        pkgs.glib
        pkgs.gtk4
        pkgs.harfbuzz
        pkgs.librsvg
        pkgs.libsoup_3
        pkgs.pango
        pkgs.nettle
        pkgs.pcsclite
        pkgs.openssl
      ];
      postInstall =
        let
          libs = [ pkgs.openssl pkgs.nettle pkgs.gmp pkgs.bzip2 pkgs.pcsclite pkgs.gtk4 pkgs.pango pkgs.glib ];
        in
        ''
          rm $out/bin/generate_jsonschema
          wrapProgram $out/bin/passworth-server --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath libs}
          wrapProgram $out/bin/passworth --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath libs}
          (cd $out/bin; ln -s passworth pw)
        '';
    };
  };
  wasmUnbound = buildRust {
    extra.CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
    root = ./wasm;
  };
  nativeId = "me.isandrew.passworth";
  browserIdKeyChrome = "TODO";
  browserIdChrome = "TODO";
  browserIdFirefox = "TODO";
  browser = derivation {
    name = "posStatic";
    system = builtins.currentSystem;
    builder = "${pkgs.bash}/bin/bash";
    args = [
      (pkgs.writeText "browserBuilder" ''
        set -xeu
        ${pkgs.coreutils}/bin/cp -r ${../skeleton} skeleton
        
        # Assemble browser bits
        ${pkgs.coreutils}/bin/mkdir -p browser_stage
        ${native}/bin/bind_wasm --in-wasm ${wasmUnbound}/bin/content.wasm --out-name content2 --out-dir browser_stage
        ${native}/bin/bind_wasm --in-wasm ${wasmUnbound}/bin/popup.wasm --out-name popup --out-dir browser_stage

        ${pkgs.coreutils}/bin/cp -r skeleton/browser_static $out/browser_chrome
        ${pkgs.coreutils}/bin/cp -r browser_stage/* $out/browser_chrome/
        chrome_browser_manifest_path=out/browser_chrome/manifest.json
        ${hoj}/bin/hoj f:skeleton/browser_manifest.json merge f:./skeleton/browser_manifest_chrome.json > $chrome_browser_manifest_path
        ${hoj}/bin/hoj --in-place f:$chrome_browser_manifest_path replace '"_PLACEHOLDER_BROWSERIDKEY"' "${browserIdKeyChrome}"
        
        ${pkgs.coreutils}/bin/cp -r skeleton/browser/static $out/browser_firefox
        ${pkgs.coreutils}/bin/cp -r browser_stage/* $out/browser_firefox/
        firefox_browser_manifest_path=out/browser_firefox/manifest.json
        ${hoj}/bin/hoj f:skeleton/browser_manifest.json merge f:./skeleton/browser_manifest_firefox.json > $firefox_browser_manifest_path
        ${hoj}/bin/hoj --in-place f:$firefox_browser_manifest_path replace '"_PLACEHOLDER_BROWSERID"' "${browserIdFirefox}"

        # Assemble native bits
        ${pkgs.coreutils}/bin/mkdir -p $out/native
        ${pkgs.coreutils}/bin/cp ${native}/bin/passworth-browser $out/native/binary
        ${hoj}/bin/hoj --in-place f:skeleton/native_manifest.json replace '"_PLACEHOLDER_BINPATH"' "$out/native/binary"
        ${hoj}/bin/hoj --in-place f:skeleton/native_manifest.json replace '"_PLACEHOLDER_NATIVEID"' "${nativeId}"

        ${hoj}/bin/hoj f:skeleton/native_manifest.json merge f:skeleton/native_manifest_chrome.json > $out/native/manifest_chrome.json
        ${hoj}/bin/hoj --in-place f:$out/native/manifest_chrome.json replace '"_PLACEHOLDER_BROWSERID"' "chrome-extension://${browserIdChrome}/"

        firefox_native_manifest_dir=$out/lib/mozilla/native-messaging-hosts/       
        ${pkgs.coreutils}/bin/mkdir -p $firefox_native_manifest_dir
        ${hoj}/bin/hoj f:skeleton/native_manifest.json merge f:/skeleton/native_manifest_firefox.json > $firefox_native_manifest_dir/${nativeId}.json
        ${hoj}/bin/hoj --in-place f:$firefox_native_manifest_dir/${nativeId}.json replace '"_PLACEHOLDER_BROWSERID"' "${browserIdFirefox}"

      '')
    ];
  };
in
{
  package = native;
  browserModule = { ... }: {
    config = {
      environment.etc = {
        # Locates binary, allows access from extensions
        "chromium/native-messaging-hosts/${nativeId}.json".source = "${browser}/native/manifest_chrome.json";
        "opt/chrome/native-messaging-hosts/${nativeId}.json".source = "${browser}/native/manifest_chrome.json";
        "opt/vivaldi/native-messaging-hosts/${nativeId}.json".source = "${browser}/native/manifest_vivaldi.json";
        "opt/brave/native-messaging-hosts/${nativeId}.json".source = "${browser}/native/manifest_brave.json";

        # Installs extension, not sure why there's only one id
        #"chromium/policies/managed/${nativeId}.json".source = "${browser}/browser/policy_chrome.json";
        #"opt/chrome/policies/managed/${nativeId}.json".source = "${browser}/browser/policy_chrome.json";
        #"opt/vivaldi/policies/managed/${nativeId}.json".source = "${browser}/browser/policy_chrome.json";
        #"opt/brave/policies/managed/${nativeId}.json".source = "${browser}/browser/policy_chrome.json";
      };

      # Locates binary, allows access from extensions
      programs.firefox.nativeMessagingHosts.packages = [ browser ];
    };
  };
}

