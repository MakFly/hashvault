#!/bin/sh
# Install an extracted release. Never starts a service or overwrites vault data.
set -eu

release_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
install_prefix=/usr/local
install_services=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --from) release_dir=$2; shift 2 ;;
    --prefix) install_prefix=$2; shift 2 ;;
    --services) install_services=true; shift ;;
    *) printf '%s\n' 'usage: install.sh [--from RELEASE_DIR] [--prefix PREFIX] [--services]' >&2; exit 2 ;;
  esac
done
case "$install_prefix" in /*) ;; *) printf '%s\n' 'prefix must be absolute' >&2; exit 2 ;; esac
if [ "$install_services" = true ] && [ "$install_prefix" != /usr/local ]; then
  printf '%s\n' '--services requires the /usr/local prefix used by the units' >&2
  exit 2
fi
release_version=$(cat "$release_dir/VERSION")
case "$release_version" in ''|*[!a-zA-Z0-9._-]*) printf '%s\n' 'invalid release version' >&2; exit 1 ;; esac
for executable in hashvault hashvaultd hashvault-agent; do
  test -f "$release_dir/bin/$executable" || { printf 'release is missing %s\n' "$executable" >&2; exit 1; }
done
test -f "$release_dir/share/hashvault/ui/index.html" || { printf '%s\n' 'release is missing UI assets' >&2; exit 1; }
install -d "$install_prefix/bin" "$install_prefix/share/hashvault"
# Versioned asset directories keep an interrupted update from replacing only
# half of the console. Each release carries its own version file.
asset_dir="$install_prefix/share/hashvault/ui-$release_version"
if [ ! -d "$asset_dir" ]; then
  cp -R "$release_dir/share/hashvault/ui" "$asset_dir"
fi
install_stage=$(mktemp -d "$install_prefix/bin/.hashvault-install-XXXXXX")
trap 'rm -rf "$install_stage"' EXIT HUP INT TERM
for executable in hashvault hashvaultd hashvault-agent; do
  install -m 0755 "$release_dir/bin/$executable" "$install_stage/$executable"
done
ln -s "ui-$release_version" "$install_stage/ui-link"
mv -Tf "$install_stage/ui-link" "$install_prefix/share/hashvault/ui"
for executable in hashvault hashvaultd hashvault-agent; do
  mv -f "$install_stage/$executable" "$install_prefix/bin/$executable"
done
if [ "$install_services" = true ]; then
  install -d /etc/systemd/system
  for unit in hashvaultd openbao hashvault-materialize; do
    install -m 0644 "$release_dir/deploy/systemd/$unit.service" "/etc/systemd/system/$unit.service"
  done
  printf '%s\n' 'Units installed. Create the service accounts and configuration, then run the bootstrap ceremony described in docs/operations.md.'
fi
printf 'Hashvault %s installed in %s\n' "$release_version" "$install_prefix"
