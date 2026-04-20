#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  CMDmap — Installer (v4.0)
#  Professional setup for the Hellhound ecosystem
# ─────────────────────────────────────────────────────────────────────

set -e

# Colors
RED='\033[91m'
GRN='\033[92m'
CYN='\033[96m'
YLW='\033[93m'
WHT='\033[97m'
RST='\033[0m'
BLD='\033[1m'

info()    { echo -e "${CYN}[*]${RST} $1"; }
success() { echo -e "${GRN}${BLD}[✓]${RST} $1"; }
warn()    { echo -e "${YLW}[!]${RST} $1"; }
error()   { echo -e "${RED}[✗]${RST} $1"; stop_animation; exit 1; }

# ── Animator Logic (Cinematic) ────────────────────────────────────────────────
ANIM_PID=0

start_animation() {
    local label="$1"
    stop_animation
    
    python3 -c "
import math, time, sys
label = \"$label\"
def wave(label, t):
    res = ''
    for i, c in enumerate(label):
        if not c.isalpha(): res += c; continue
        v = math.sin(t * 10 + i * 0.4)
        if v > 0: res += f'\033[91m\033[1m{c.upper()}\033[0m'
        else: res += f'\033[31m{c.lower()}\033[0m'
    return res
def braille(t):
    chars = '⡀⡄⡆⡇⣇⣧⣷⣿'
    bar = ''
    for i in range(15):
        idx = int((math.sin(t * 5 + i * 0.3) + 1) / 2 * (len(chars) - 1))
        bar += f'\033[91m{chars[idx]}\033[0m'
    return bar
start = time.time()
try:
    while True:
        t = time.time() - start
        sys.stdout.write(f'\r \033[96m[*]\033[0m {wave(label, t)}  {braille(t)}')
        sys.stdout.flush()
        time.sleep(0.06)
except KeyboardInterrupt:
    pass
" &
    ANIM_PID=$!
}

stop_animation() {
    if [ "$ANIM_PID" -ne 0 ]; then
        kill "$ANIM_PID" &>/dev/null || true
        wait "$ANIM_PID" 2>/dev/null || true
        printf "\r\b\b\033[K"
        ANIM_PID=0
    fi
}

trap "stop_animation" EXIT INT TERM

# ── Sanity Checks ─────────────────────────────────────────────────────────────
start_animation "PREPARING CORE"

if ! command -v python3 &>/dev/null; then
    stop_animation
    error "Python 3 not found. Install Python 3.10+ and try again."
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    error "Python 3.10+ required. Found: $PY_VERSION"
fi

# ── Virtual Environment Setup ──────────────────────────────────────────────────
start_animation "ISOLATING SYSTEM"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR" || error "Failed to create virtual environment. Ensure 'python3-venv' is installed."
fi
VENV_PYTHON="$VENV_DIR/bin/python3"

# ── Install Dependencies ───────────────────────────────────────────────────────
start_animation "MOUNTING LIBRARIES"
"$VENV_PYTHON" -m pip install --quiet --upgrade pip
if [ -f "requirements.txt" ]; then
    "$VENV_PYTHON" -m pip install --quiet -r requirements.txt
fi

# ── Playwright Setup ──────────────────────────────────────────────────────────
if "$VENV_PYTHON" -c "import playwright" &>/dev/null; then
    start_animation "SYCHRONIZING BROWSERS"
    "$VENV_PYTHON" -m playwright install chromium
fi

# ── Wrapper Generation ─────────────────────────────────────────────────────────
start_animation "FINALIZING ENGINE"

CMD_SRC="$SCRIPT_DIR/CMDmap.py"
if [ ! -f "$CMD_SRC" ]; then
    error "CMDmap.py not found in $SCRIPT_DIR"
fi

WRAPPER_TMP=$(mktemp)
cat << EOW > "$WRAPPER_TMP"
#!/usr/bin/env bash
# CMDmap — Wrapper Script
# Generated on $(date)
"$VENV_PYTHON" "$CMD_SRC" "\$@"
EOW

# ── Smart Deployment ───────────────────────────────────────────────────────────
if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
elif sudo -n true 2>/dev/null; then
    INSTALL_DIR="/usr/local/bin"
    USE_SUDO=true
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

INSTALL_PATH="$INSTALL_DIR/cmdmap"

if [ "${USE_SUDO:-false}" = true ]; then
    sudo cp "$WRAPPER_TMP" "$INSTALL_PATH"
    sudo chmod +x "$INSTALL_PATH"
else
    cp "$WRAPPER_TMP" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
fi
rm -f "$WRAPPER_TMP"

stop_animation
success "Installed to $INSTALL_PATH"

# PATH Advice if needed
if [ "$INSTALL_DIR" = "$HOME/.local/bin" ]; then
    if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
        warn "$HOME/.local/bin is not in your PATH"
        echo ""
        echo "  Add this line to your ~/.bashrc or ~/.zshrc:"
        echo -e "    ${GRN}export PATH=\"\$HOME/.local/bin:\$PATH\"${RST}"
        echo ""
    fi
fi

echo ""
success "Setup Complete. Run 'cmdmap --help' to verify."
echo ""
