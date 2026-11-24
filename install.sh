#!/bin/sh
# Installs the hardenkit CLI.
#
#   curl -sSfL https://hardenkit.com/install.sh | sh
#
# Environment:
#   HARDENKIT_VERSION       version to install (default: latest release)
#   HARDENKIT_INSTALL_DIR   where to put the binary (default: /usr/local/bin
#                           if writable, otherwise ~/.local/bin)
set -eu

repo="hardenkit/scan"

fail() { echo "hardenkit install: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }

need curl
need tar
need uname

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported OS $(uname -s); download a build from https://github.com/$repo/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac

version="${HARDENKIT_VERSION:-}"
if [ -z "$version" ]; then
  # /releases/latest skips pre-releases and the rolling "db" data release.
  version=$(curl -sSfL -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest" | sed 's|.*/tag/||')
  [ -n "$version" ] && [ "$version" != "latest" ] || fail "could not find the latest release"
fi
version="${version#v}"

name="hardenkit_${version}_${os}_${arch}"
base="https://github.com/$repo/releases/download/v$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading hardenkit $version for $os/$arch ..."
curl -sSfL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz" || fail "download failed: $base/$name.tar.gz"
curl -sSfL -o "$tmp/checksums.txt" "$base/checksums.txt" || fail "checksum download failed"

expected=$(grep " $name.tar.gz\$" "$tmp/checksums.txt" | cut -d' ' -f1)
[ -n "$expected" ] || fail "no checksum listed for $name.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for $name.tar.gz"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"

dir="${HARDENKIT_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir"
mv "$tmp/$name/hardenkit" "$dir/hardenkit"
chmod +x "$dir/hardenkit"

echo "Installed $("$dir/hardenkit" version) to $dir/hardenkit"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH to run hardenkit from anywhere." ;;
esac
