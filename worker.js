const GITHUB_REPO = "https://github.com/anulman/ugrant";
const GITHUB_API_LATEST = "https://api.github.com/repos/anulman/ugrant/releases/latest";
const WWW_HOST = "www.ugrant.sh";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.protocol === "http:") {
      url.protocol = "https:";
      return Response.redirect(url.toString(), 301);
    }

    if (url.hostname === "ugrant.sh") {
      url.hostname = WWW_HOST;
      return Response.redirect(url.toString(), 301);
    }

    if (url.pathname === "/github") {
      return Response.redirect(GITHUB_REPO, 302);
    }

    if (url.pathname === "/install") {
      return redirectInstall(request);
    }

    if (url.pathname === "/install.sh") {
      return new Response(INSTALL_SCRIPT, {
        headers: {
          "content-type": "text/x-shellscript; charset=utf-8",
          "cache-control": "public, max-age=300",
        },
      });
    }

    return env.ASSETS.fetch(request);
  },
};

async function redirectInstall(request) {
  const fallback = `${GITHUB_REPO}/releases/latest`;
  const url = new URL(request.url);
  const target = url.searchParams.get("target") || pickRequestedArtifact(request.headers.get("user-agent") || "");
  if (!target) {
    return Response.redirect(fallback, 302);
  }

  try {
    const response = await fetch(GITHUB_API_LATEST, {
      headers: {
        "User-Agent": "ugrant.sh",
        Accept: "application/vnd.github+json",
      },
      cf: { cacheTtl: 300, cacheEverything: true },
    });
    if (!response.ok) {
      return Response.redirect(fallback, 302);
    }

    const release = await response.json();
    const assets = Array.isArray(release.assets) ? release.assets : [];
    const match = assets.find((asset) => typeof asset?.name === "string" && asset.name.includes(target));
    if (match?.browser_download_url) {
      return Response.redirect(match.browser_download_url, 302);
    }
  } catch {
    // fall through to latest release page
  }

  return Response.redirect(fallback, 302);
}

function pickRequestedArtifact(userAgent) {
  const ua = userAgent.toLowerCase();
  const isMac = /mac os x|macintosh|darwin/.test(ua);
  const isLinux = /linux/.test(ua) && !/android/.test(ua);
  const isArm64 = /arm64|aarch64/.test(ua) || /mac os x.*arm|applewebkit.*arm/.test(ua);
  const isX64 = /x86_64|win64|x64|amd64|intel/.test(ua);

  if (isMac && isArm64) return "-macos-arm64.tar.gz";
  if (isMac && isX64) return "-macos-x86_64.tar.gz";
  if (isLinux && isArm64) return "-linux-aarch64.tar.gz";
  if (isLinux && isX64) return "-linux-x86_64.tar.gz";
  return null;
}

const INSTALL_SCRIPT = String.raw`#!/bin/sh
set -eu

BASE_URL="https://www.ugrant.sh"
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux) os="linux" ;;
  Darwin) os="macos" ;;
  *)
    echo "Unsupported OS: $OS" >&2
    echo "See https://github.com/anulman/ugrant/releases/latest" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    echo "See https://github.com/anulman/ugrant/releases/latest" >&2
    exit 1
    ;;
esac

if [ "$os" = "linux" ] && [ "$arch" = "arm64" ]; then
  target="linux-aarch64"
else
  target="$os-$arch"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

curl -fsSL "$BASE_URL/install?target=$target" -o "$tmpdir/ugrant.tar.gz"
tar -xzf "$tmpdir/ugrant.tar.gz" -C "$tmpdir"

binary="$(find "$tmpdir" -type f -name ugrant | head -n 1)"
if [ -z "$binary" ]; then
  echo "Could not find ugrant binary in downloaded archive" >&2
  exit 1
fi

install_dir="\${HOME}/.local/bin"
mkdir -p "$install_dir"
cp "$binary" "$install_dir/ugrant"
chmod +x "$install_dir/ugrant"

echo "Installed ugrant to $install_dir/ugrant"
echo "Make sure $install_dir is on your PATH"
`;
