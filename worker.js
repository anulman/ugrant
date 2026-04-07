const GITHUB_REPO = "https://github.com/anulman/ugrant";
const GITHUB_API_LATEST = "https://api.github.com/repos/anulman/ugrant/releases/latest";
const WWW_HOST = "www.ugrant.sh";
const SUPPORTED_TARGETS = new Set(["linux-x86_64", "linux-aarch64", "macos-x86_64", "macos-arm64"]);
const MINISIGN_PUBLIC_KEY_COMMENT = "minisign public key for ugrant releases";
const MINISIGN_PUBLIC_KEY = "RWROMGoscMzrnBn4DAQctEu3E+Y5totRluTj+M/IT0w6ZIuaNjkepTAB";
const MINISIGN_PUBLIC_KEY_FILE = `untrusted comment: ${MINISIGN_PUBLIC_KEY_COMMENT}\n${MINISIGN_PUBLIC_KEY}\n`;
const INSTALL_KIND_SUFFIX = {
  archive: "",
  sha256: ".sha256",
  minisig: ".minisig",
};

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

    if (url.pathname === "/minisign.pub") {
      return new Response(MINISIGN_PUBLIC_KEY_FILE, {
        headers: {
          "content-type": "text/plain; charset=utf-8",
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
  const requestedTarget = url.searchParams.get("target") || pickRequestedArtifact(request.headers.get("user-agent") || "");
  const target = normalizeTarget(requestedTarget);
  const kind = normalizeInstallKind(url.searchParams.get("kind"));

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
      return new Response("Could not resolve the latest GitHub release metadata.", { status: 502 });
    }

    const release = await response.json();
    const tag = typeof release?.tag_name === "string" ? release.tag_name : null;
    const assets = Array.isArray(release.assets) ? release.assets : [];
    if (!tag) {
      return new Response("Latest GitHub release is missing a tag name.", { status: 502 });
    }

    const expectedName = `ugrant-${tag}-${target}.tar.gz${INSTALL_KIND_SUFFIX[kind]}`;
    const match = assets.find((asset) => typeof asset?.name === "string" && asset.name === expectedName);
    if (match?.browser_download_url) {
      return Response.redirect(match.browser_download_url, 302);
    }

    return new Response(`Could not find release asset: ${expectedName}`, { status: 404 });
  } catch {
    return new Response("Could not reach GitHub to resolve the requested release asset.", { status: 502 });
  }
}

function normalizeInstallKind(kind) {
  if (kind === "sha256") return "sha256";
  if (kind === "minisig") return "minisig";
  return "archive";
}

function normalizeTarget(target) {
  return SUPPORTED_TARGETS.has(target) ? target : null;
}

function pickRequestedArtifact(userAgent) {
  const ua = userAgent.toLowerCase();
  const isMac = /mac os x|macintosh|darwin/.test(ua);
  const isLinux = /linux/.test(ua) && !/android/.test(ua);
  const isArm64 = /arm64|aarch64/.test(ua) || /mac os x.*arm|applewebkit.*arm/.test(ua);
  const isX64 = /x86_64|win64|x64|amd64|intel/.test(ua);

  if (isMac && isArm64) return "macos-arm64";
  if (isMac && isX64) return "macos-x86_64";
  if (isLinux && isArm64) return "linux-aarch64";
  if (isLinux && isX64) return "linux-x86_64";
  return null;
}

const INSTALL_SCRIPT = String.raw`#!/bin/sh
set -eu

BASE_URL="https://www.ugrant.sh"
MINISIGN_PUBLIC_KEY="RWROMGoscMzrnBn4DAQctEu3E+Y5totRluTj+M/IT0w6ZIuaNjkepTAB"
OS="$(uname -s)"
ARCH="$(uname -m)"
verification_summary=""

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
  arm64|aarch64)
    if [ "$os" = "linux" ]; then
      arch="aarch64"
    else
      arch="arm64"
    fi
    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    echo "See https://github.com/anulman/ugrant/releases/latest" >&2
    exit 1
    ;;
esac

target="$os-$arch"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

archive="$tmpdir/ugrant.tar.gz"
signature="$tmpdir/ugrant.tar.gz.minisig"
checksum="$tmpdir/ugrant.tar.gz.sha256"

download_archive() {
  curl -fsSL "$BASE_URL/install?target=$target" -o "$archive"
}

download_signature() {
  curl -fsSL "$BASE_URL/install?target=$target&kind=minisig" -o "$signature"
}

download_checksum() {
  curl -fsSL "$BASE_URL/install?target=$target&kind=sha256" -o "$checksum"
}

verify_checksum() {
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmpdir" && sha256sum -c "$(basename "$checksum")")
    return
  fi

  if command -v shasum >/dev/null 2>&1; then
    (cd "$tmpdir" && shasum -a 256 -c "$(basename "$checksum")")
    return
  fi

  if command -v openssl >/dev/null 2>&1; then
    expected="$(awk '{print $1}' "$checksum")"
    actual="$(openssl dgst -sha256 -r "$archive" | awk '{print $1}')"
    [ "$expected" = "$actual" ] || {
      echo "Checksum verification failed" >&2
      exit 1
    }
    return
  fi

  echo "Need sha256sum, shasum, or openssl to verify the download" >&2
  exit 1
}

verify_archive() {
  if command -v minisign >/dev/null 2>&1 && [ "$MINISIGN_PUBLIC_KEY" != "RWROMGoscMzrnBn4DAQctEu3E+Y5totRluTj+M/IT0w6ZIuaNjkepTAB" ]; then
    download_signature
    minisign -Vm "$archive" -P "$MINISIGN_PUBLIC_KEY" -x "$signature"
    verification_summary="Verified release signature with minisign"
    return
  fi

  if command -v minisign >/dev/null 2>&1; then
    echo "minisign is installed, but this installer does not have an embedded public key yet. Falling back to checksum verification." >&2
  else
    echo "minisign not found, falling back to checksum verification. Install minisign for stronger release authenticity checks." >&2
  fi

  download_checksum
  verify_checksum
  verification_summary="Verified archive checksum (compatibility fallback)"
}

download_archive
verify_archive

tar -xzf "$archive" -C "$tmpdir"

binary="$(find "$tmpdir" -type f -name ugrant | head -n 1)"
if [ -z "$binary" ]; then
  echo "Could not find ugrant binary in downloaded archive" >&2
  exit 1
fi

install_dir="$HOME/.local/bin"
mkdir -p "$install_dir"
cp "$binary" "$install_dir/ugrant"
chmod +x "$install_dir/ugrant"

echo "Installed ugrant to $install_dir/ugrant"
echo "$verification_summary"
echo "Make sure $install_dir is on your PATH"
`;
