{ pkgs, lib, debug ? true }:
let
  hoj = import ((fetchTarball "https://github.com/andrewbaxter/hammer-of-json/archive/4622456e0eeffd62380dbd88d648c28c8a3359d9.zip") + "/source/package.nix") { pkgs = pkgs; lib = lib; };
  rust = import ./rust.nix { pkgs = pkgs; lib = lib; };

  wasmUnbound = import ./nixbuild/wasm { pkgs = pkgs; lib = lib; debug = debug; };
  nativeId = "me.isandrew.passworth";
  extensionIdKeyChrome = "TODO";
  extensionIdChrome = "TODO";
  #extensionIdFirefox = "365d2ed012492eb0cff650b7e191c1da5488b5eb@temporary-addon";
  extensionIdFirefox = "passworth@example.org";
in
{
  nativeId = nativeId;
  extensionUnpacked = derivation {
    name = "passworth-browser-unpacked";
    system = builtins.currentSystem;
    builder = "${pkgs.bash}/bin/bash";
    args = [
      (pkgs.writeText "browserBuilder" ''
        set -xeu -o pipefail

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
        cp ${./browser} browser_src
        
        # Assemble browser bits
        ${pkgs.coreutils}/bin/mkdir -p browser_wasm
        ${pkgs.passworth}/bin/bind_wasm --in-wasm ${wasmUnbound}/bin/browser-popup.wasm --out-name popup2 --out-dir browser_wasm
        version=$(${pkgs.gnugrep}/bin/grep "^version =" ${./shared/Cargo.toml} | ${pkgs.gnused}/bin/sed -e "s/.*\"\(.*\)\".*/\1/")
        set browser_src/browser_manifest.json _PLACEHOLDER_VERSION "$version"

        cp browser_src/ext_static stage/browser_chrome
        cp browser_wasm/* stage/browser_chrome/
        chrome_browser_manifest_path=stage/browser_chrome/manifest.json
        merge browser_src/browser_manifest.json ./browser_src/browser_manifest_chrome.json > $chrome_browser_manifest_path
        set $chrome_browser_manifest_path _PLACEHOLDER_BROWSERIDKEY '${extensionIdKeyChrome}'
        
        cp browser_src/ext_static stage/browser_firefox
        cp browser_wasm/* stage/browser_firefox/
        firefox_browser_manifest_path=stage/browser_firefox/manifest.json
        merge browser_src/browser_manifest.json ./browser_src/browser_manifest_firefox.json > $firefox_browser_manifest_path
        set $firefox_browser_manifest_path _PLACEHOLDER_BROWSERID '${extensionIdFirefox}'

        # Assemble native bits
        ${pkgs.coreutils}/bin/mkdir -p stage/native
        cp ${pkgs.passworth}/bin/passworth-browser stage/native/binary
        set browser_src/native_manifest.json _PLACEHOLDER_BINPATH "$out/native/binary"
        set browser_src/native_manifest.json _PLACEHOLDER_NATIVEID '${nativeId}'

        merge browser_src/native_manifest.json browser_src/native_manifest_chrome.json > stage/native/manifest_chrome.json
        set stage/native/manifest_chrome.json _PLACEHOLDER_BROWSERID 'chrome-extension://${extensionIdChrome}/'

        firefox_native_manifest_dir=stage/lib/mozilla/native-messaging-hosts/       
        ${pkgs.coreutils}/bin/mkdir -p $firefox_native_manifest_dir
        merge browser_src/native_manifest.json browser_src/native_manifest_firefox.json > $firefox_native_manifest_dir/${nativeId}.json
        set $firefox_native_manifest_dir/${nativeId}.json _PLACEHOLDER_BROWSERID '${extensionIdFirefox}'

        cp stage $out
        ${pkgs.coreutils}/bin/chmod a+x $out/native/binary

        ${pkgs.web-ext}/bin/web-ext lint --output json --pretty --self-hosted --source-dir $out/browser_firefox
      '')
    ];
  };
}


