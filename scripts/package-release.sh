#!/usr/bin/env bash
# Release packaging only. This script is never a development-server entrypoint.
set -euo pipefail
release_version=${1:?usage: package-release.sh VERSION OS ARCH}
release_os=${2:?release OS required}
release_arch=${3:?release architecture required}
case "$release_version" in ''|*[!a-zA-Z0-9._-]*) exit 2 ;; esac
case "$release_os/$release_arch" in linux/amd64|linux/arm64) ;; *) exit 2 ;; esac
release_work=$(mktemp -d)
trap 'rm -rf "$release_work"' EXIT
release_root="$release_work/hashvault"
mkdir -p "$release_root/bin" "$release_root/share/hashvault" dist
bun install --frozen-lockfile
bun run --cwd ui build
cp -R ui/dist "$release_root/share/hashvault/ui"
for executable in hashvault hashvaultd hashvault-agent; do
  GOOS="$release_os" GOARCH="$release_arch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/MakFly/hashvault/internal/cli.Version=$release_version -X github.com/MakFly/hashvault/internal/server.Version=$release_version -X github.com/MakFly/hashvault/internal/agentcli.Version=$release_version" -o "$release_root/bin/$executable" "./cmd/$executable"
done
cp -R deploy docs "$release_root/"
mkdir -p "$release_root/scripts"
cp scripts/install.sh "$release_root/scripts/"
printf '%s\n' "$release_version" > "$release_root/VERSION"
release_archive="hashvault-$release_version-$release_os-$release_arch.tar.gz"
tar -czf "dist/$release_archive" -C "$release_work" hashvault
(cd dist && sha256sum "$release_archive" > "$release_archive.sha256")
