#!/bin/sh
# 从当前源码构建并安装 jumpctl。默认安装到 ~/.local/bin，可用 BIN_DIR 覆盖。
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BIN_DIR=${BIN_DIR:-"$HOME/.local/bin"}
TARGET="$BIN_DIR/jumpctl"

if ! command -v go >/dev/null 2>&1; then
    echo "jumpctl install: Go toolchain not found in PATH" >&2
    exit 1
fi

version=$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)
mkdir -p "$BIN_DIR"
temporary=$(mktemp "$BIN_DIR/.jumpctl-install.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM

echo "Building jumpctl ($version)..."
(
    cd "$REPO_ROOT"
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$temporary" ./cmd/jumpctl
)
chmod 755 "$temporary"
mv -f "$temporary" "$TARGET"
trap - EXIT HUP INT TERM

echo "Installed $TARGET ($version)"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "note: $BIN_DIR is not in PATH; add it before running jumpctl" ;;
esac
"$TARGET" version
