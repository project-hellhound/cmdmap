#!/bin/bash

# CMDmap Uninstaller

set -e

echo -e "\033[1;31m[-] Removing CMDmap Environment...\033[0m"

# Remove symlink
BIN_DEST="/usr/local/bin/cmdmap"
if [ -L "$BIN_DEST" ]; then
    sudo rm "$BIN_DEST" 2>/dev/null || rm "$BIN_DEST" 2>/dev/null
    echo -e "\033[1;32m[+] Removed global link $BIN_DEST\033[0m"
fi

# Remove venv
if [ -d ".venv" ]; then
    rm -rf .venv
    echo -e "\033[1;32m[+] Removed virtual environment (.venv)\033[0m"
fi

# Remove build artifacts
rm -rf *.egg-info build/ dist/

echo -e "\033[1;31m[-] Cleanup Complete.\033[0m"
