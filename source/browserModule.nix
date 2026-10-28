{ config, pkgs, lib, ... }:
let
  browser = import ./browser.nix {
    pkgs = pkgs;
    lib = lib;
    debug = true;
    publicSuffixList = config.passworth.browser.publicSuffixList;
  };
in
{
  imports = [
    ./nixbuild/native
  ];
  options.passworth.browser.publicSuffixList = lib.mkOption {
    type = lib.types.path;
    default = import ./nixbuild/publicSuffixList.nix { pkgs = pkgs; };
    defaultText = lib.literalExpression "import ./nixbuild/publicSuffixList.nix { pkgs = pkgs; }";
    description = ''
      Copy of the public suffix list compiled into the browser extension popup, used to
      pick the default search path from the current site's registrable domain. The
      default is a pinned upstream copy; point this at a newer file to refresh it.
    '';
  };
  config = {
    environment.etc = {
      # Locates binary, allows access from extensions
      "chromium/native-messaging-hosts/${browser.nativeId}.json".source = "${browser.extensionUnpacked}/native/manifest_chrome.json";
      "opt/chrome/native-messaging-hosts/${browser.nativeId}.json".source = "${browser.extensionUnpacked}/native/manifest_chrome.json";
      "opt/vivaldi/native-messaging-hosts/${browser.nativeId}.json".source = "${browser.extensionUnpacked}/native/manifest_vivaldi.json";
      "opt/brave/native-messaging-hosts/${browser.nativeId}.json".source = "${browser.extensionUnpacked}/native/manifest_brave.json";

      # Installs extension, not sure why there's only one id
      #"chromium/policies/managed/${nativeId}.json".source = "${extensionUnpacked}/browser/policy_chrome.json";
      #"opt/chrome/policies/managed/${nativeId}.json".source = "${extensionUnpacked}/browser/policy_chrome.json";
      #"opt/vivaldi/policies/managed/${nativeId}.json".source = "${extensionUnpacked}/browser/policy_chrome.json";
      #"opt/brave/policies/managed/${nativeId}.json".source = "${extensionUnpacked}/browser/policy_chrome.json";
    };

    # Locates binary, allows access from extensions
    programs.firefox.nativeMessagingHosts.packages = [ browser.extensionUnpacked ];

    # Make it available in packages
    nixpkgs.overlays = [
      (finalPkgs: prevPkgs: {
        passworthExtensionUnpacked = browser.extensionUnpacked;
      })
    ];
  };
}
