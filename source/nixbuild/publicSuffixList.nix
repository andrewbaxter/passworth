# Pinned copy of the public suffix list, compiled into the browser extension popup.
# Update the commit and hash to refresh it.
{ pkgs }: pkgs.fetchurl {
  url = "https://raw.githubusercontent.com/publicsuffix/list/8437e5262f13305f94087abe699b4fe2be1d1de8/public_suffix_list.dat";
  hash = "sha256-0+YkO1FpUyeYSrs+KlqnB3CWhn91Eh4DHmpaOEDKi80=";
}
