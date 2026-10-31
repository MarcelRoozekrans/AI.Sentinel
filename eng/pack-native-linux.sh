#!/bin/sh
# Packs one Linux RID tool package with Native AOT inside a build container, called by
# .github/workflows/native-cli.yml as: docker run ... <image> sh eng/pack-native-linux.sh
#
# A Native AOT binary needs the glibc of the machine it was linked on, or newer. The glibc RIDs
# build in AlmaLinux 8 (glibc 2.28), so the binary starts on every glibc distro .NET 10 supports,
# RHEL 8 and SLES 15 included. The musl RIDs build in the Alpine .NET SDK image.
#
# Environment: PROJECT (csproj path), RID, VERSION.
set -eu

if [ -f /etc/alpine-release ]; then
  apk add --no-cache clang build-base zlib-dev bash curl
else
  dnf install -y --setopt=install_weak_deps=False clang zlib-devel libicu findutils tar gzip curl
fi

# `dotnet --version` also fails when the image's SDK does not satisfy global.json.
if ! dotnet --version >/dev/null 2>&1; then
  curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
  bash /tmp/dotnet-install.sh --jsonfile global.json --install-dir /usr/share/dotnet
  export PATH="/usr/share/dotnet:$PATH"
fi
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1

dotnet pack "$PROJECT" -c Release -r "$RID" \
  -p:PackageVersion="$VERSION" -p:Version="$VERSION" -o out
