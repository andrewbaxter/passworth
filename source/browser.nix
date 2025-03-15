{ pkgs, lib, debug ? true }:
let
  hoj = import ((fetchTarball "https://github.com/andrewbaxter/hammer-of-json/archive/4622456e0eeffd62380dbd88d648c28c8a3359d9.zip") + "/source/package.nix") { pkgs = pkgs; lib = lib; };
  rust = import ./rust.nix { pkgs = pkgs; lib = lib; };

  wasmUnbound = import ./nixbuild/wasm { pkgs = pkgs; lib = lib; debug = debug; };
  nativeId = "me.isandrew.passworth";
  extensionIdKeyChrome = "TODO";
  extensionIdChrome = "TODO";
  extensionIdFirefox = "passworth@example.org";
in
{
  nativeId = nativeId;
  extensionUnpacked = pkgs.runCommand "passworth-browser-unpacked" { } ''
    hoj_cp () {
      ${pkgs.coreutils}/bin/cp -r --no-preserve=all "$@"
    }
    hoj_merge () {
      ${hoj}/bin/hoj "f:$1" merge "f:$2"
    }
    hoj_set () {
      ${hoj}/bin/hoj --in-place "f:$1" search-set "\"$2\"" "\"$3\""
    }

    ${pkgs.coreutils}/bin/mkdir -p stage
    hoj_cp ${./browser} browser_src
        
    # Assemble browser bits
    ${pkgs.coreutils}/bin/mkdir -p browser_wasm
    ${pkgs.passworth}/bin/bind_wasm --in-wasm ${wasmUnbound}/bin/browser-popup.wasm --out-name popup2 --out-dir browser_wasm
    version=$(${pkgs.gnugrep}/bin/grep "^version =" ${./shared/Cargo.toml} | ${pkgs.gnused}/bin/sed -e "s/.*\"\(.*\)\".*/\1/")
    hoj_set browser_src/browser_manifest.json _PLACEHOLDER_VERSION "$version"

    hoj_cp browser_src/ext_static stage/browser_chrome
    hoj_cp browser_wasm/* stage/browser_chrome/
    chrome_browser_manifest_path=stage/browser_chrome/manifest.json
    hoj_merge browser_src/browser_manifest.json ./browser_src/browser_manifest_chrome.json > $chrome_browser_manifest_path
    hoj_set $chrome_browser_manifest_path _PLACEHOLDER_BROWSERIDKEY '${extensionIdKeyChrome}'
        
    hoj_cp browser_src/ext_static stage/browser_firefox
    hoj_cp browser_wasm/* stage/browser_firefox/
    firefox_browser_manifest_path=stage/browser_firefox/manifest.json
    hoj_merge browser_src/browser_manifest.json ./browser_src/browser_manifest_firefox.json > $firefox_browser_manifest_path
    hoj_set $firefox_browser_manifest_path _PLACEHOLDER_BROWSERID '${extensionIdFirefox}'

    # Assemble native bits
    ${pkgs.coreutils}/bin/mkdir -p stage/native
    hoj_cp ${pkgs.passworth}/bin/passworth-browser stage/native/binary
    hoj_set browser_src/native_manifest.json _PLACEHOLDER_BINPATH "$out/native/binary"
    hoj_set browser_src/native_manifest.json _PLACEHOLDER_NATIVEID '${nativeId}'

    hoj_merge browser_src/native_manifest.json browser_src/native_manifest_chrome.json > stage/native/manifest_chrome.json
    hoj_set stage/native/manifest_chrome.json _PLACEHOLDER_BROWSERID 'chrome-extension://${extensionIdChrome}/'

    firefox_native_manifest_dir=stage/lib/mozilla/native-messaging-hosts/       
    ${pkgs.coreutils}/bin/mkdir -p $firefox_native_manifest_dir
    hoj_merge browser_src/native_manifest.json browser_src/native_manifest_firefox.json > $firefox_native_manifest_dir/${nativeId}.json
    hoj_set $firefox_native_manifest_dir/${nativeId}.json _PLACEHOLDER_BROWSERID '${extensionIdFirefox}'

    hoj_cp stage $out
    ${pkgs.coreutils}/bin/chmod a+x $out/native/binary

    ${pkgs.web-ext}/bin/web-ext lint --output json --pretty --self-hosted --source-dir $out/browser_firefox
  '';
}


