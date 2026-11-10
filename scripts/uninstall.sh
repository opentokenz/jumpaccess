#!/bin/sh
# 删除 install.sh 安装的 jumpctl。默认位置 ~/.local/bin，可用 BIN_DIR 覆盖。
set -eu

BIN_DIR=${BIN_DIR:-"$HOME/.local/bin"}
TARGET="$BIN_DIR/jumpctl"

if [ ! -e "$TARGET" ]; then
    echo "jumpctl is not installed at $TARGET"
    exit 0
fi

rm -f "$TARGET"
echo "Removed $TARGET"
echo "Profiles, aliases, and credentials were kept in the application data directory:"
case "$(uname -s)" in
    Darwin) echo "  $HOME/Library/Application Support/JumpAccess" ;;
    *) echo "  ${XDG_CONFIG_HOME:-$HOME/.config}/JumpAccess" ;;
esac
echo "Delete that directory manually to remove them as well."
