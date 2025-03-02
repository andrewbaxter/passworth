{ pkgs, lib }:
let
  hoj = import ((fetchTarball "https://github.com/andrewbaxter/hammer-of-json/archive/4622456e0eeffd62380dbd88d648c28c8a3359d9.zip") + "/source/package.nix") { pkgs = pkgs; lib = lib; };
  fenix = import (fetchTarball "https://github.com/nix-community/fenix/archive/1a79901b0e37ca189944e24d9601c8426675de50.zip") { };
  naersk = pkgs.callPackage (fetchTarball "https://github.com/nix-community/naersk/archive/378614f37a6bee5a3f2ef4f825a73d948d3ae921.zip") (
    let
      toolchain = fenix.combine [
        fenix.latest.rustc
        fenix.latest.cargo
        fenix.targets.wasm32-unknown-unknown.latest.rust-std
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
  extensionIdKeyChrome = "TODO";
  extensionIdChrome = "TODO";
  #extensionIdFirefox = "365d2ed012492eb0cff650b7e191c1da5488b5eb@temporary-addon";
  extensionIdFirefox = "passworth@example.org";
  extensionUnpacked = derivation {
    name = "passworth-browser-unpacked";
    system = builtins.currentSystem;
    builder = "${pkgs.bash}/bin/bash";
    args = [
      (pkgs.writeText "browserBuilder" ''
        set -xeu

        cp () {
          ${pkgs.coreutils}/bin/cp -r --no-preserve=all "$@"
        }
        merge () {
          ${hoj}/bin/hoj "f:$1" merge "f:$2"
        }
        set () {
          ${hoj}/bin/hoj --in-place "f:$1" search-set "\"$2\"" "\"$3\""
        }

        ${pkgs.coreutils}/bin/mkdir -p stage
        cp ${./skeleton} skeleton
        
        # Assemble browser bits
        ${pkgs.coreutils}/bin/mkdir -p browser_wasm
        ${native}/bin/bind_wasm --in-wasm ${wasmUnbound}/bin/popup.wasm --out-name popup2 --out-dir browser_wasm

        cp skeleton/ext_static stage/browser_chrome
        cp browser_wasm/* stage/browser_chrome/
        chrome_browser_manifest_path=stage/browser_chrome/manifest.json
        merge skeleton/browser_manifest.json ./skeleton/browser_manifest_chrome.json > $chrome_browser_manifest_path
        set $chrome_browser_manifest_path _PLACEHOLDER_BROWSERIDKEY '${extensionIdKeyChrome}'
        
        cp skeleton/ext_static stage/browser_firefox
        cp browser_wasm/* stage/browser_firefox/
        firefox_browser_manifest_path=stage/browser_firefox/manifest.json
        merge skeleton/browser_manifest.json ./skeleton/browser_manifest_firefox.json > $firefox_browser_manifest_path
        set $firefox_browser_manifest_path _PLACEHOLDER_BROWSERID '${extensionIdFirefox}'

        # Assemble native bits
        ${pkgs.coreutils}/bin/mkdir -p stage/native
        cp ${native}/bin/passworth-browser stage/native/binary
        set skeleton/native_manifest.json _PLACEHOLDER_BINPATH "$out/native/binary"
        set skeleton/native_manifest.json _PLACEHOLDER_NATIVEID '${nativeId}'

        merge skeleton/native_manifest.json skeleton/native_manifest_chrome.json > stage/native/manifest_chrome.json
        set stage/native/manifest_chrome.json _PLACEHOLDER_BROWSERID 'chrome-extension://${extensionIdChrome}/'

        firefox_native_manifest_dir=stage/lib/mozilla/native-messaging-hosts/       
        ${pkgs.coreutils}/bin/mkdir -p $firefox_native_manifest_dir
        merge skeleton/native_manifest.json skeleton/native_manifest_firefox.json > $firefox_native_manifest_dir/${nativeId}.json
        set $firefox_native_manifest_dir/${nativeId}.json _PLACEHOLDER_BROWSERID '${extensionIdFirefox}'

        cp stage $out
        ${pkgs.coreutils}/bin/chmod a+x $out/native/binary

        ${pkgs.web-ext}/bin/web-ext lint --output json --pretty --self-hosted --source-dir $out/browser_firefox
      '')
    ];
  };
in
{
  package = native;
  extensionUnpacked = extensionUnpacked;
  browserModule = { ... }: {
    config = {
      environment.etc = {
        # Locates binary, allows access from extensions
        "chromium/native-messaging-hosts/${nativeId}.json".source = "${extensionUnpacked}/native/manifest_chrome.json";
        "opt/chrome/native-messaging-hosts/${nativeId}.json".source = "${extensionUnpacked}/native/manifest_chrome.json";
        "opt/vivaldi/native-messaging-hosts/${nativeId}.json".source = "${extensionUnpacked}/native/manifest_vivaldi.json";
        "opt/brave/native-messaging-hosts/${nativeId}.json".source = "${extensionUnpacked}/native/manifest_brave.json";

        # Installs extension, not sure why there's only one id
        #"chromium/policies/managed/${nativeId}.json".source = "${extensionUnpacked}/browser/policy_chrome.json";
        #"opt/chrome/policies/managed/${nativeId}.json".source = "${extensionUnpacked}/browser/policy_chrome.json";
        #"opt/vivaldi/policies/managed/${nativeId}.json".source = "${extensionUnpacked}/browser/policy_chrome.json";
        #"opt/brave/policies/managed/${nativeId}.json".source = "${extensionUnpacked}/browser/policy_chrome.json";
      };

      # Locates binary, allows access from extensions
      programs.firefox.nativeMessagingHosts.packages = [ extensionUnpacked ];
    };
  };
}

