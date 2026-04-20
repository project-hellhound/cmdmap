#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  CMDmap — Updater
#  Pulls the latest changes and refreshes the environment
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

# ── Animator Logic ────────────────────────────────────────────────────────────
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

# ── Execution ─────────────────────────────────────────────────────────────────

# Check if Git repository
start_animation "VERIFYING SOURCE"
if [ ! -d ".git" ]; then
    stop_animation
    error "Not a git repository. Use 'git clone' to use the updater."
fi

# Pull latest changes
start_animation "FETCHING UPDATES"
LOCAL_CHANGES=$(git status --porcelain)
if [ -n "$LOCAL_CHANGES" ]; then
    warn "Local changes detected — stashing..."
    git stash
fi

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
if git pull origin "$CURRENT_BRANCH"; then
    stop_animation
    success "Source updated [branch: $CURRENT_BRANCH]"
else
    stop_animation
    warn "Pull failed — check your connection or conflicts."
fi

# Restore stash
if [ -n "$LOCAL_CHANGES" ]; then
    info "Restoring local changes..."
    git stash pop &>/dev/null || true
fi

# Refresh installation
start_animation "REFRESHING ENV"
chmod +x install.sh
./install.sh
stop_animation

echo ""
success "Update Complete. You are on the latest version."
echo ""
