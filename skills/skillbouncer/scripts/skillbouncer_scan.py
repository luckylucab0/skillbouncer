#!/usr/bin/env python3
"""
skillbouncer_scan.py - static security scanner for agent skills and plugins.

Purpose
-------
Before a third-party skill (SKILL.md + references/ + scripts/ + assets/) or
plugin is installed, this script looks for typical patterns of prompt
injection, data exfiltration, credential access, dangerous shell commands
and obfuscation.

Why static and without dependencies?
  * The script reads the content under review as text only. It runs
    nothing from it, imports nothing from it and makes no network
    requests. A malicious skill therefore cannot attack the scanner.
  * Standard library only, so it runs in any sandbox and needs no
    third-party packages (which would be a supply-chain risk themselves).

Important: the scanner is a filter, not a verdict. It finds candidates that
a human or Claude must then read in context. An empty report means "no
known patterns", not "safe". Semantic manipulation in fluent prose is only
caught by reading the content (see SKILL.md, step 4).

Script analysis (since 1.1.0)
-----------------------------
Files with executable code get three more checks:
  * Malware rules (MAL-*): stealers, keyloggers, ransomware, miners,
    disabling antivirus, anti-forensics, downloading further code.
  * Capabilities per script (network, secrets, directory walks, processes
    ...) and their combination (COMBO-*). On its own "reads ~/.aws" or
    "makes HTTP requests" is often harmless; both in one script is the
    typical shape of an exfiltration (source -> sink). The list appears as
    the "script inventory" in the report and is the starting point for
    reading the code in full (references/script-analysis.md).
  * Manifests that run or download code automatically on install or
    start: package.json install hooks, requirements.txt with Git/URL
    sources, .mcp.json, hooks.json.
Embedded Base64 payloads are checked for file signatures (PE, ELF, Mach-O,
ZIP ...), because hidden binaries would otherwise slip through as "does
not decode to text".

Usage
-----
    python3 -I skillbouncer_scan.py PATH [PATH ...] [--json report.json]
                                    [--min-severity LOW]

PATH may be a folder with many skills, a single skill folder, or a
ZIP-based archive (.zip, .skill, .plugin, .whl ...; extracted safely into
a temp directory).

"-I" (isolated mode) is deliberate: Python then loads no modules from the
current directory. If the repo under review contains a planted "json.py",
it would otherwise run on "import json".

Exit codes: 0 = only LOW/INFO, 1 = at least MEDIUM, 2 = at least HIGH.
That makes the scanner usable as a gate in CI or scripts.
"""

import argparse
import base64
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unicodedata
import zipfile
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Severities
# ---------------------------------------------------------------------------
# Order matters: the index is used for filtering (--min-severity) and for
# the exit code.
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH"]


def sev_rank(sev):
    return SEVERITIES.index(sev)


# ---------------------------------------------------------------------------
# File types
# ---------------------------------------------------------------------------
# Text files whose content Claude may read or run.
TEXT_EXT = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".csv", ".tsv", ".html", ".htm",
    ".xml", ".xsd", ".svg", ".css", ".py", ".js", ".mjs", ".cjs", ".ts", ".sh",
    ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".rb", ".pl", ".toml", ".ini",
    ".cfg", ".sql", ".jinja", ".j2", ".tpl", ".ipynb", "",
}
# Files with executable code: always read by hand, because SKILL.md may
# tell Claude to start them. Deliberately broad: Windows script formats
# (vbs, hta, wsf) that run on double click, and sources that are built
# first (go, rs, c), because an instruction "build and run this" makes
# them just as executable.
CODE_EXT = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash",
    ".zsh", ".fish", ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs",
    ".wsf", ".hta", ".rb", ".pl", ".php", ".lua", ".applescript",
    ".command", ".ipynb", ".go", ".rs", ".java", ".kt", ".swift", ".c",
    ".cpp", ".cs",
}
# Files without a (distinctive) extension that still run code, e.g. on
# "make", "docker build" or "pip install" (setup.py runs then).
CODE_NAMES = {
    "Makefile", "makefile", "GNUmakefile", "Dockerfile", "Containerfile",
    "justfile", "Justfile", "Rakefile", "Gemfile", "setup.py", "conftest.py",
}
# Harmless binary formats (fonts, images, PDF templates). Other binaries
# (exe, so, dll, jar, pyc ...) have no place in an instruction skill and
# are rated high.
BENIGN_BINARY_EXT = {
    ".ttf", ".otf", ".woff", ".woff2", ".png", ".jpg", ".jpeg", ".gif",
    ".webp", ".ico", ".pdf", ".mp3", ".wav", ".mp4",
}
DANGEROUS_BINARY_EXT = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".class", ".pyc",
    ".pyo", ".msi", ".app", ".deb", ".rpm", ".apk", ".scr", ".com", ".node",
    ".wasm", ".lnk", ".vbe", ".jse", ".scpt", ".xlsm", ".docm", ".pptm",
    ".iso", ".img", ".dmg", ".vhd", ".vhdx", ".pkg", ".elf", ".o", ".a",
}
# Nested archives: the scanner does not unpack these (zip bombs, endless
# recursion). Their content is therefore unchecked and has to be
# extracted and scanned separately. .gz used to be listed as harmless,
# but a .tar.gz can contain scripts just as well.
NESTED_ARCHIVE_EXT = {
    ".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".zst",
    ".skill", ".plugin", ".whl", ".egg", ".crx", ".xpi", ".vsix",
}
# Signatures (magic bytes) of executable or packed content. They reveal
# Base64 payloads in code that decode to a binary ("dropper": the
# program sits in the script as a string).
EXEC_MAGIC = [
    (b"MZ", "Windows program (PE/EXE/DLL)"),
    (b"\x7fELF", "Linux program (ELF)"),
    (b"\xcf\xfa\xed\xfe", "macOS program (Mach-O)"),
    (b"\xce\xfa\xed\xfe", "macOS program (Mach-O)"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal / Java class"),
    (b"\x00asm", "WebAssembly module"),
    (b"\xe3\x00\x00\x00", "Python bytecode (marshal)"),
]
# Archives: may contain programs, but also occur as test data (e.g. a
# Base64 ZIP in a unit test). Hence MEDIUM, not HIGH.
ARCHIVE_MAGIC = [
    (b"PK\x03\x04", "ZIP archive (possibly JAR/wheel/plugin)"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!", "RAR archive"),
]
# Signatures of harmless media: embedded images/fonts are normal.
BENIGN_MAGIC = [
    b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"%PDF", b"RIFF", b"wOFF", b"wOF2",
    b"\x00\x01\x00\x00", b"OTTO", b"ID3", b"<svg", b"<?xml", b"\x00\x00\x01\x00",
]

MAX_TEXT_BYTES = 5_000_000        # read larger text files only in part
LARGE_TEXT_WARN = 1_000_000       # very large reference files = good hiding place
ZIP_MAX_TOTAL = 300_000_000       # zip-bomb guard during extraction
ZIP_MAX_MEMBERS = 20_000

# ---------------------------------------------------------------------------
# Invisible / direction-changing Unicode characters
# ---------------------------------------------------------------------------
# These hide instructions that are invisible in an editor but read by the
# model ("ASCII smuggling" via tag characters, Trojan Source via bidi
# overrides, steganography via the Variation Selectors Supplement).
INVISIBLE_RANGES = [
    (0x200B, 0x200C, "Zero-Width Space/Non-Joiner"),
    (0x200E, 0x200F, "LTR/RTL Mark"),
    (0x202A, 0x202E, "Bidi-Embedding/Override"),
    (0x2060, 0x2064, "Word Joiner/invisible operators"),
    (0x2066, 0x2069, "Bidi-Isolate"),
    (0x180E, 0x180E, "Mongolian Vowel Separator"),
    (0xE0000, 0xE007F, "Unicode tag characters (ASCII smuggling)"),
    (0xE0100, 0xE01EF, "Variation Selectors Supplement (steganography)"),
]


def is_emoji_like(ch):
    """Rough emoji detection, so that ZWJ (U+200D) inside emoji sequences such
    as family emoji is not reported."""
    cp = ord(ch)
    return (0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF
            or 0x2300 <= cp <= 0x23FF or cp in (0xFE0F, 0x2640, 0x2642))


def find_invisible(text):
    """Returns a list of (line number, description) for hidden characters."""
    hits = []
    line = 1
    for i, ch in enumerate(text):
        if ch == "\n":
            line += 1
            continue
        cp = ord(ch)
        if cp == 0x200D:
            # ZWJ between two emoji is normal (e.g. skin-tone sequences).
            prev_ch = text[i - 1] if i > 0 else ""
            next_ch = text[i + 1] if i + 1 < len(text) else ""
            if prev_ch and next_ch and is_emoji_like(prev_ch) and is_emoji_like(next_ch):
                continue
            hits.append((line, "Zero-Width Joiner outside emoji"))
            continue
        if cp == 0xFEFF and i > 0:
            # A BOM at the start of a file is normal, in the middle of text it is not.
            hits.append((line, "BOM/Zero-Width No-Break Space inside text"))
            continue
        for lo, hi, label in INVISIBLE_RANGES:
            if lo <= cp <= hi:
                hits.append((line, label))
                break
    return hits


def decode_tag_chars(text):
    """Unicode tag characters (U+E0020..U+E007E) mirror ASCII. If a skill
    contains them, the hidden plain text is shown as well, so the reviewer
    sees what was being smuggled."""
    out = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    return out


# ---------------------------------------------------------------------------
# Homoglyphs: Latin and Cyrillic/Greek letters in the same word. Typical
# for spoofed domains ("аnthropic.com" with a Cyrillic а) or for getting
# around word filters.
# ---------------------------------------------------------------------------
WORD_RE = re.compile(r"[^\W\d_]{3,}", re.UNICODE)


def mixed_script_words(line):
    found = []
    for w in WORD_RE.findall(line):
        scripts = set()
        for ch in w:
            name = unicodedata.name(ch, "")
            if name.startswith("LATIN"):
                scripts.add("Latin")
            elif name.startswith("CYRILLIC"):
                scripts.add("Cyrillic")
            elif name.startswith("GREEK"):
                scripts.add("Greek")
        if "Latin" in scripts and len(scripts) > 1:
            found.append(w)
    return found


# ---------------------------------------------------------------------------
# Rules for text patterns
# ---------------------------------------------------------------------------
# Each rule: (id, severity, description, regex, code_only)
# code_only=True means the rule applies to script files only, because the
# pattern would cause too many false alarms in prose (e.g. "requests" as
# a word).
#
# The rules are deliberately broad. The goal is high recall; sorting out
# false alarms happens in the triage step, in context.
I = re.IGNORECASE
RULES = [
    # --- Prompt injection: attempts to override system/user instructions
    ("INJ-OVERRIDE", "HIGH", "Tells the assistant to ignore earlier instructions",
     re.compile(r"\b(ignore|disregard|forget|override|bypass)\b.{0,25}\b(all|any|the|your|previous|prior|above|earlier|system|safety|other)\b.{0,25}\b(instructions?|rules|prompts?|guidelines|polic(y|ies)|guardrails|restrictions)\b", I), False),
    ("INJ-OVERRIDE-DE", "HIGH", "Tells the assistant to ignore instructions (German)",
     re.compile(r"\b(ignorier|vergiss|missacht|umgeh)\w*\b.{0,30}\b(anweisung|regel|vorgabe|richtlinie|sicherheit)\w*", I), False),
    ("INJ-ROLE", "MEDIUM", "Role switch / jailbreak phrasing",
     re.compile(r"\b(you are now|from now on you are|new (system )?instructions|developer mode|jailbreak|DAN mode|act as (an? )?unrestricted|no longer bound)\b", I), False),
    ("INJ-SPOOF", "MEDIUM", "Forged system/turn markers",
     re.compile(r"(<\|im_start\|>|<\|system\|>|</?system>|\[SYSTEM\]|\[INST\]|^\s*(Human|Assistant|System)\s*:\s)", I | re.M), False),
    ("INJ-AUTHORITY", "MEDIUM", "Claimed authority / pre-approval",
     re.compile(r"\b(anthropic (has )?(authori[sz]ed|requires|approved)|pre-?authori[sz]ed|the user (has )?already (approved|consented|authori[sz]ed)|official instruction from|admin override)\b", I), False),
    ("DECEPT-HIDE", "HIGH", "Hiding something from the user",
     re.compile(r"\b(do not|don't|never)\s+(tell|inform|mention|reveal|show|disclose|notify)\b.{0,30}\b(the user|users|anyone|this)\b|\bwithout (telling|informing|notifying|alerting) (the )?user\b|\bhide (this|it|these) from\b|\bkeep (this|it) (a )?secret\b", I), False),
    ("DECEPT-HIDE-DE", "HIGH", "Hiding something from the user (German)",
     re.compile(r"\b(ohne (den|die) (nutzer|benutzer|user)\w* zu (informieren|fragen|benachrichtigen)|sag\w* (dem|der) (nutzer|benutzer|user)\w* nicht|verheimlich\w*)\b", I), False),
    ("DECEPT-SILENT", "MEDIUM", "Silent action (silently/quietly + action)",
     re.compile(r"\b(silently|quietly|secretly|covertly|in the background)\b.{0,20}\b(send|upload|post|run|execute|install|delete|forward|copy|exfiltrate|share)\b", I), False),

    # --- Data exfiltration
    ("EXFIL-SERVICE", "HIGH", "Known exfiltration/tunnel/paste service",
     re.compile(r"(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|trycloudflare\.com|serveo\.net|localtunnel|loca\.lt|pastebin\.com|paste\.ee|hastebin|transfer\.sh|file\.io|0x0\.st|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator|canarytokens|beeceptor|hookbin)", I), False),
    ("EXFIL-IMG", "HIGH", "Markdown image/link with dynamic placeholders (classic exfiltration channel)",
     re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]*(\{\{|\$\{|\$[A-Z_]{3,}|<[a-z_]+>|\{[a-z_]+\})", I), False),
    ("EXFIL-PARAM", "MEDIUM", "URL carries sensitive data as a parameter",
     re.compile(r"https?://[^\s)\"'>]*[?&](data|payload|conversation|chat|history|token|key|secret|password|pwd|cookie|session|email|content)=", I), False),
    ("EXFIL-SEND", "MEDIUM", "Instruction to send conversation or user data to an outside party",
     re.compile(r"\b(send|post|upload|forward|transmit|submit)\b.{0,40}\b(conversation|chat history|transcript|user'?s? (data|files|messages|credentials|emails?)|system prompt|environment variables|api keys?)\b.{0,40}\b(to|via)\b", I), False),
    ("NET-RAW-IP", "MEDIUM", "URL pointing at a bare IP address",
     re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?", I), False),
    ("NET-SHORTENER", "LOW", "URL shortener hides the destination",
     re.compile(r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|rb\.gy|cutt\.ly|ow\.ly|shorturl\.at|tiny\.cc)/", I), False),

    # --- Access to secrets
    # "Login Data" (Chrome's password database) lives in MAL-STEALER-BROWSER
    # with a path separator in front; matched case-insensitively it used to
    # report ordinary prose like "login data is stored" as HIGH.
    ("SECRET-PATH", "HIGH", "Access to key/credential stores",
     re.compile(r"(~/\.ssh|\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials|\.netrc\b|\.git-credentials|/etc/(passwd|shadow)|\bkeychain\b|\.config/gcloud|\.kube/config|\.docker/config\.json|wallet\.dat|\.npmrc|\.pypirc|\.azure/|gh/hosts\.yml|\.claude/\.credentials|\.vault-token|\.terraform\.d/credentials|/proc/(self|\d+|\*)/environ|\.(bash|zsh)_history)", I), False),
    ("SECRET-CLOUD-META", "HIGH", "Query to the cloud metadata service (returns instance credentials)",
     re.compile(r"(169\.254\.169\.254|169\.254\.170\.2|fd00:ec2::254|metadata\.google\.internal|metadata\.azure\.com|/latest/meta-data|/computeMetadata/)", I), False),
    # A single named variable (os.getenv("FOO_API_KEY")) is normal. What
    # stands out is a script collecting ALL variables: in sandboxes these
    # often hold tokens the skill has no need for.
    # os.environ.copy() / {**os.environ} are left out on purpose: that mostly
    # just passes the environment on to a subprocess.
    ("SECRET-ENV-DUMP", "MEDIUM", "Reads all environment variables at once (instead of one named variable)",
     re.compile(r"(os\.environ\.(items|keys|values)\(\)|json\.dumps\(\s*(dict\()?\s*os\.environ|str\(\s*os\.environ\s*\)|for\s+\w+(\s*,\s*\w+)?\s+in\s+os\.environ\b|JSON\.stringify\(\s*process\.env\b|Object\.(keys|entries|values)\(\s*process\.env\s*\)|GetEnvironmentVariables\(\))", I), True),
    ("SECRET-ENV", "MEDIUM", "Reads environment variables/.env",
     re.compile(r"(\bprintenv\b|\benv\s*\||\bcat\s+[^\n]*\.env\b|\bread (the )?\.env\b|\bset\s*>|Get-ChildItem\s+env:)", I), False),
    ("SECRET-ASK", "LOW", "Asks for a password/API key/token",
     re.compile(r"\b(ask|prompt|request)\b.{0,30}\b(the user|them|user)\b.{0,30}\b(password|passphrase|api[ _-]?key|access token|secret key|private key|seed phrase|2fa|otp)\b", I), False),

    # --- Dangerous shell patterns
    ("SHELL-PIPE", "HIGH", "Runs a download directly in a shell",
     re.compile(r"(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(sudo\s+)?((ba|z|da)?sh|iex|python3?|node|perl|ruby)\b|\biex\s*\(|Invoke-Expression|powershell[^\n]*-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh|eval\s+\"?\$\((curl|wget)", I), False),
    ("SHELL-REVERSE", "HIGH", "Reverse shell / network backdoor",
     re.compile(r"(/dev/tcp/|\bnc\s+(-[a-z]*e|-c)\b|\bncat\b.*-e|\bmkfifo\b|\bsocat\b.*exec|bash\s+-i\s+>&)", I), False),
    ("SHELL-DESTRUCT", "HIGH", "Destructive command",
     re.compile(r"(\brm\s+-[a-z]*r[a-z]*f?\s+(/|~|\$HOME|\*)(\s|$)|\bmkfs\.|\bdd\s+if=.*of=/dev/|:\(\)\s*\{\s*:\|:&\s*\};:|\bchmod\s+-R\s+777\s+/)", I), False),
    ("SHELL-PERSIST", "HIGH", "Persistence (autostart, cron, shell profiles)",
     re.compile(r"(\bcrontab\b|\blaunchctl\s+load\b|systemctl\s+enable\b|>>\s*~?/?\.?(bash|zsh)rc\b|>>\s*~/\.profile|\bschtasks\b|HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run)", I), False),
    ("SHELL-SUDO", "MEDIUM", "Elevated privileges (sudo/runas)",
     re.compile(r"(^|\s|`)(sudo|runas|doas)\s+\S", I), False),
    ("SHELL-INSTALL", "MEDIUM", "Package installation (supply-chain risk, check the origin)",
     re.compile(r"\b(pip3?\s+install|npm\s+(install|i)\s|npx\s+-?[a-z@]|pnpm\s+(add|dlx)|yarn\s+(add|dlx)|bunx\s|gem\s+install|go\s+install|cargo\s+install|brew\s+install|uvx\s|pipx\s+run)", I), False),
    ("SHELL-POST", "LOW", "HTTP POST from the command line",
     re.compile(r"\bcurl\b[^\n]*(-X\s*POST|--data|\s-d\s|-F\s|--upload-file)", I), False),

    # --- Obfuscation (code)
    ("OBF-DECODE", "MEDIUM", "Runtime decoding/dynamic execution",
     # (?<![.\w]) excludes method calls such as regex.exec(...) or
     # re.compile(...). Those are harmless and everywhere in JS/Python; only
     # the free-standing builtins exec()/eval()/compile() are dangerous.
     re.compile(r"(\batob\s*\(|String\.fromCharCode|base64\.b64decode|codecs\.decode|bytes\.fromhex|(?<![.\w])exec\s*\(|(?<![.\w])eval\s*\(|(?<![.\w])compile\s*\(|__import__\s*\(|marshal\.loads|pickle\.loads|new Function\s*\()", I), True),
    ("OBF-HEX", "MEDIUM", "Long hex/escape sequence",
     re.compile(r"(\\x[0-9a-f]{2}){12,}|(\\u[0-9a-f]{4}){12,}", I), False),

    # --- Network / processes in scripts: not a finding as such, but inventory
    ("CODE-NET", "LOW", "Script accesses the network",
     re.compile(r"\b(requests\.(get|post|put|delete|request)|urllib\.request|urlopen|http\.client|socket\.socket|aiohttp|httpx\.|fetch\s*\(|XMLHttpRequest|axios\.|WebSocket\s*\()", I), True),
    ("CODE-PROC", "LOW", "Script starts processes",
     re.compile(r"\b(subprocess\.|os\.system|os\.popen|child_process|execSync|spawn\s*\(|Runtime\.getRuntime)", I), True),
    ("CODE-HOME", "MEDIUM", "Script reads in the home directory",
     re.compile(r"(os\.path\.expanduser\(|Path\.home\(\)|os\.homedir\(\)|\$HOME/|%USERPROFILE%)", I), True),

    # --- Tampering with memory/configuration
    ("PERSIST-MEMORY", "MEDIUM", "Writes to the assistant's memory/configuration",
     re.compile(r"(\bCLAUDE\.md\b|\bmemory_(write|append|str_replace)\b|\bsave (this|these|it) (to|in) (your )?memory\b|~/\.claude\b|\.claude/settings|\badd (this )?to (your|the) system prompt\b|\bupdate (the user'?s|your) preferences\b)", I), False),
    ("AUTONOMY", "MEDIUM", "Acts without asking the user",
     re.compile(r"\b(without (asking|confirmation|approval|user approval|permission)|do not ask (for )?(permission|confirmation|approval)|never ask (for )?(permission|confirmation)|automatically (send|post|publish|purchase|buy|pay|delete|submit))\b", I), False),

    # --- Hidden content in Markdown/HTML
    ("HIDDEN-HTML", "MEDIUM", "HTML content hidden via CSS",
     re.compile(r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0[;\"']|color\s*:\s*(#fff(fff)?|white)\s*;\s*background\s*:\s*(#fff(fff)?|white))", I), False),

    # =======================================================================
    # Malware patterns in scripts (since 1.1.0)
    # =======================================================================
    # Grouped by what malicious code typically does. Most rules apply to prose
    # as well (code_only=False), because a SKILL.md can just as well tell
    # Claude to run the command itself. Rules made of common words run on
    # code only, otherwise prose floods the report.

    # --- Download and run ("dropper"/"loader")
    ("MAL-DOWNLOAD-EXEC", "HIGH", "Downloads code from the network and runs it",
     re.compile(r"((?<![.\w])(exec|eval)\s*\(\s*(await\s+)?(requests\.\w+|urlopen|urllib\.request\.urlopen|httpx\.\w+|fetch|https?\.get|axios\.get)\s*\(|(bash|sh|zsh|source)\s+<\(\s*(curl|wget)|(python3?|node|perl|ruby|php)\s+-[ce]\s+[\"']?\$\((curl|wget)|sh\s+-c\s+[\"']?\$\((curl|wget)|DownloadString\(|DownloadFile\([^\n]{0,200}\.(exe|ps1|bat|dll|scr|vbs|msi)|Start-BitsTransfer|certutil(\.exe)?\s[^\n]{0,200}-urlcache|bitsadmin\s+/transfer|mshta(\.exe)?\s+[\"']?(https?:|javascript:|vbscript:)|regsvr32[^\n]{0,200}/i:\s*https?:|rundll32[^\n]{0,200}(javascript:|https?:)|(urlretrieve|wget|curl)\b[^\n]{0,200}&&\s*(chmod\s+\+x|\./))", I), False),
    ("MAL-DECODE-EXEC", "HIGH", "Decodes data and runs it directly",
     re.compile(r"((?<![.\w])(exec|eval|compile)\s*\(\s*([\w.]*\.)?(b64decode|b32decode|a85decode|decompress|loads|fromhex|atob|unhexlify)\s*\(|(?<![.\w])(exec|eval)\s*\(\s*[\"'][^\"']*[\"']\s*\[::-1\]|(?<![.\w])(exec|eval)\s*\(\s*(bytes|bytearray)\(|(?<![.\w])(exec|eval)\s*\(\s*(''|\"\")\.join|(?<![.\w])eval\s*\(\s*Buffer\.from\(|new\s+Function\s*\(\s*atob\(|FromBase64String[^\n]{0,200}(\biex\b|Invoke-Expression)|(\biex\b|Invoke-Expression)[^\n]{0,200}FromBase64String)", I), True),
    ("OBF-INDIRECT", "MEDIUM", "Indirect access to builtins (evades a pattern search for exec/eval)",
     re.compile(r"(getattr\(\s*(__builtins__|builtins|globals\(\))\s*,|__builtins__\s*\.\s*__dict__|__builtins__\s*\[|globals\(\)\s*\[\s*[\"']|[\"']ex[\"']\s*\+\s*[\"']ec[\"']|[\"']ev[\"']\s*\+\s*[\"']al[\"']|[\"']sys[\"']\s*\+\s*[\"']tem[\"']|\[\s*[\"']constructor[\"']\s*\]\s*\(|coding[:=]\s*(rot.?13|unicode.escape|raw.unicode.escape|utf.?7))", I), True),

    # --- Information theft ("stealer")
    # Case-sensitive and with a path separator in front: "Local State" or
    # "Web Data" are otherwise ordinary words in UI documentation.
    ("MAL-STEALER-BROWSER", "HIGH", "Access to browser profiles (saved passwords, cookies, keys)",
     re.compile(r"([/\\\"']Login Data\b|[/\\\"']Local State\b|[/\\\"']Web Data\b|\bkey[34]\.db\b|\blogins\.json\b|cookies\.sqlite|\bCryptUnprotectData\b|Mozilla[/\\]+Firefox[/\\]+Profiles|\.mozilla/firefox|Google[/\\]+Chrome[/\\]+User Data|Application Support/Google/Chrome|BraveSoftware[/\\]+Brave-Browser|Microsoft[/\\]+Edge[/\\]+User Data|find-(generic|internet)-password|security\s+dump-keychain|browser_cookie3|\bpycookiecheat\b)"), False),
    ("MAL-STEALER-APPS", "HIGH", "Access to app session tokens or crypto wallets",
     re.compile(r"(discord(canary|ptb)?[/\\]+Local Storage|Local Storage[/\\]+leveldb|Telegram Desktop[/\\]+tdata|[/\\]tdata[/\\]|Slack[/\\]+(Cookies|storage)|Teams[/\\]+(Cookies|Local Storage)|[/\\](Exodus|Electrum|Atomic|Armory|Ethereum|Bitcoin)[/\\]+(wallets?|keystore|exodus\.wallet)|nkbihfbeogaeaoehlefnkodbefgpgknn|Local Extension Settings)", I), False),
    ("MAL-KEYLOG", "HIGH", "Records keystrokes (keylogger)",
     re.compile(r"(pynput\.keyboard|\bkeyboard\.(on_press|on_release|hook|record)\b|\bGetAsyncKeyState\b|\bSetWindowsHookEx\w*|\bWH_KEYBOARD(_LL)?\b|CGEventTapCreate|xinput\s+test\b|/dev/input/event|\biohook\b|node-global-key-listener)", I), True),
    ("MAL-SPY-CAPTURE", "MEDIUM", "Reads screen, clipboard, camera or microphone",
     re.compile(r"(ImageGrab\.grab|pyautogui\.screenshot|\bmss\(\)|\bscreencapture\b|\bscrot\b|desktopCapturer|getDisplayMedia|pyperclip\.paste|\bpbpaste\b|xclip\s[^\n]{0,200}-o\b|xsel\s+(-o|--output|-b)\b|Get-Clipboard|clipboard\.read(Text)?\(|win32clipboard|cv2\.VideoCapture|getUserMedia|\bpyaudio\b|sounddevice\.rec|\bimagesnap\b|\bffmpeg\b[^\n]{0,200}-f\s+(avfoundation|dshow|v4l2|alsa|pulse|gdigrab|x11grab))", I), True),
    ("MAL-RECON", "MEDIUM", "Reconnaissance of system, network or domain",
     re.compile(r"(whoami\s+/(all|priv|groups)|\bnet\s+(user|group|localgroup|view|share)\b|\bsysteminfo\b|ipconfig\s+/all|\barp\s+-a\b|\bnltest\b|Get-AD(User|Computer|Group)|\bnmap\b|\bmasscan\b|\bnetstat\s+-[a-z]*a|Get-NetTCPConnection|ifconfig\s+-a\b)", I), True),

    # --- Extortion, destruction, resource abuse
    ("MAL-RANSOM", "HIGH", "Ransomware/wiper trait (shadow copies, ransom note, renaming to .locked)",
     re.compile(r"(vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit[^\n]{0,200}recoveryenabled\s+no|wbadmin\s+delete|cipher(\.exe)?\s+/w:|your (files|data|documents) (have|has) been encrypted|decrypt\w*\s[^\n]{0,60}(bitcoin|\bbtc\b|monero|\bxmr\b|ransom)|\+\s*[\"']\.(locked|encrypted|crypted|crypt|enc|pay|ransom)[\"'])", I), False),
    ("MAL-MINER", "HIGH", "Crypto mining",
     re.compile(r"(stratum\+(tcp|ssl|tls)://|\bxmrig\b|\bxmr-stak\b|\bcpuminer\b|\bminerd\b|\bnbminer\b|\bethminer\b|\bcoinhive\b|\bcryptonight\b|\bnicehash\b|(minexmr|supportxmr|nanopool|2miners|f2pool|hashvault|moneroocean)\.\w+|--donate-level)", I), False),

    # --- Disabling protection and covering tracks
    ("MAL-EVASION", "HIGH", "Turns off antivirus, system protection, firewall or logging",
     re.compile(r"(Set-MpPreference\s[^\n]{0,200}-Disable|Add-MpPreference\s[^\n]{0,200}-Exclusion|DisableRealtimeMonitoring|DisableAntiSpyware|AmsiUtils|amsiInitFailed|AmsiScanBuffer|spctl\s+--master-disable|csrutil\s+disable|setenforce\s+0|\bufw\s+disable|systemctl\s+(stop|disable|mask)\s+(auditd|rsyslog|apparmor|firewalld|falcon|wazuh|osquery)|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off|EtwEventWrite)", I), False),
    ("MAL-EVASION-SOFT", "MEDIUM", "Starts inconspicuously (hidden window, bypasses Gatekeeper/ExecutionPolicy)",
     re.compile(r"(-ExecutionPolicy\s+(Bypass|Unrestricted)|-ep\s+bypass\b|-WindowStyle\s+Hidden|-w\s+hidden\b|CREATE_NO_WINDOW|DETACHED_PROCESS|\bpythonw(\.exe)?\b|xattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine|\b[wc]script(\.exe)?\s)", I), False),
    # Background processes are normal for local servers (nohup + disown) but
    # outlive the session. Hence only LOW and only in code: visible in the
    # script inventory without flooding the triage.
    ("CODE-BACKGROUND", "LOW", "Starts a detached background process (keeps running after the session ends?)",
     re.compile(r"(\bnohup\b|\bdisown\b|\bsetsid\b|start_new_session\s*=\s*True|detached\s*:\s*true)", I), True),
    ("MAL-ANTIFORENSIC", "HIGH", "Covers tracks (shell history, event logs, self-deletion, timestamps)",
     re.compile(r"(history\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|>\s*~?/?\.?(bash|zsh)_history|rm\s[^\n]{0,200}\.(bash|zsh)_history|wevtutil(\.exe)?\s+(cl|clear-log)|Clear-EventLog|Remove-EventLog|auditpol\s+/clear|journalctl\s+--(vacuum|rotate)|shred\s+-[a-z]*u|os\.(remove|unlink)\(\s*(__file__|sys\.argv\[0\])|unlink(Sync)?\(\s*__filename\s*\)|rm\s+(-f\s+)?[\"']?\$0[\"']?(\s|$)|Remove-Item[^\n]{0,200}\$MyInvocation|touch\s+-[a-z]*r\s|Set-ItemProperty[^\n]{0,200}(LastWriteTime|CreationTime))", I), False),
    # Thresholds per unit: Python time.sleep and shell sleep count seconds
    # (suspicious from 100 s), JS sleep()/setTimeout milliseconds (only from
    # 1000 s or ~17 min, otherwise every test timeout matches).
    ("MAL-SANDBOX-CHECK", "MEDIUM", "Detects an analysis/test environment or delays execution (time bomb?)",
     re.compile(r"(IsDebuggerPresent|CheckRemoteDebuggerPresent|sys\.gettrace\(\)|\bVBOX\w*|VirtualBox|SbieDll|sandboxie|wine_get_unix_file_name|/proc/1/cgroup|(?<![.\w])sleep\(\s*\d{6,}\s*\)|(time|asyncio)\.sleep\(\s*\d{3,}\s*\)|(^|[;&|]\s*)sleep\s+\d{3,}\b|setTimeout\([^\n]{0,200},\s*\d{7,}\s*\)|Start-Sleep\s+(-s(econds)?\s+)?\d{3,}|(datetime\.now|datetime\.today|date\.today|new Date)\(\)[^\n]{0,40}[<>]=?\s*(datetime|date|new Date)?\(?\s*20\d\d)", I), True),

    # --- Privilege escalation
    ("MAL-PRIVESC", "HIGH", "Privilege escalation (setuid, sudoers, host process namespace)",
     re.compile(r"(chmod\s+[ugoa]*\+s\b|chmod\s+[2467][0-7]{3}\s|/etc/sudoers|\bNOPASSWD\b|os\.setuid\(\s*0\s*\)|nsenter\s+[^\n]{0,200}-t\s*1\b|\bpkexec\b)", I), False),
    ("CODE-CONTAINER-ESC", "MEDIUM", "Access to the Docker socket or a privileged container (equals root on the host)",
     re.compile(r"(/var/run/docker\.sock|--privileged\b|privileged\s*:\s*true|--pid[= ]host|--cap-add[= ](SYS_ADMIN|ALL))", I), False),
    ("MAL-SHELLCODE", "HIGH", "Makes memory executable or injects code into other processes",
     re.compile(r"(VirtualAlloc(Ex)?\s*\(|VirtualProtect\s*\(|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|RtlMoveMemory|QueueUserAPC|PAGE_EXECUTE_READWRITE|mprotect\([^\n]{0,200}PROT_EXEC|mmap\([^\n]{0,200}PROT_EXEC|ptrace\(\s*PTRACE_(ATTACH|POKETEXT)|\bLD_PRELOAD=|DYLD_INSERT_LIBRARIES)", I), False),
    ("CODE-NATIVE", "MEDIUM", "Calls native libraries directly (ctypes/FFI): behaviour not visible in the source",
     re.compile(r"(\bctypes\.(windll|cdll|CDLL|WinDLL|oledll|pythonapi)|\bfrom\s+ctypes\s+import|\bimport\s+ctypes\b|\bcffi\b|ffi-napi|node-ffi|process\.dlopen|Add-Type\s[^\n]{0,200}DllImport|\[DllImport)", I), True),

    # --- Persistence and spreading
    ("MAL-PERSIST", "HIGH", "Further persistence locations (autostart, services, SSH keys, scheduled tasks)",
     re.compile(r"(\.config/autostart|Library/Launch(Agents|Daemons)|/etc/systemd/system/|\.config/systemd/user|/etc/rc\.local|/etc/init\.d/|/etc/cron\.|/var/spool/cron|>>?\s*\S*authorized_keys|authorized_keys[\"']?\s*,\s*[\"']a|Start Menu[/\\]+Programs[/\\]+Startup|CurrentVersion[/\\]+Run(Once)?\b|(New|Register)-ScheduledTask|Register-WmiEvent|__EventFilter|\bPROMPT_COMMAND=)", I), False),
    ("PERSIST-DEV", "MEDIUM", "Sets Git hooks (code then runs on every commit/checkout)",
     re.compile(r"(core\.hooksPath(?![= ]+/dev/null)|\.git/hooks/)", I), False),
    # MEDIUM, not HIGH: installers of legitimate skills (e.g. "copy to
    # .claude/skills") touch the same paths. Whether it reads or writes, and
    # what, only shows when the script is read.
    ("MAL-SKILL-TAMPER", "MEDIUM", "Script touches other skills/plugins or AI assistant configuration (does it write there?)",
     re.compile(r"(/mnt/skills\b|\.claude/(skills|plugins|settings(\.local)?\.json|hooks|agents|commands)\b|\.claude\.json\b|claude_desktop_config\.json|\.cursor/mcp\.json|\.vscode/(settings|mcp)\.json|\.codex/|\.gemini/|AppData[/\\]+Roaming[/\\]+Claude)", I), True),
    ("MAL-PUBLISH", "MEDIUM", "Publishes packages or pushes to repos (worm/supply-chain pattern)",
     re.compile(r"(\bnpm\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bgem\s+push\b|\bgit\s+push\b|\bgh\s+(repo\s+create|release\s+create|gist\s+create)\b|\bgit\s+remote\s+(add|set-url)\b)", I), True),

    # --- Outbound channels besides the usual HTTP request
    ("NET-ALT-CHANNEL", "MEDIUM", "Outbound channel besides HTTP (mail, FTP, SSH/SCP, DNS queries carrying data, messenger webhook)",
     re.compile(r"(\bsmtplib\b|\bnodemailer\b|Send-MailMessage|\bsendmail\b|\bftplib\b|ftp://|\bparamiko\b|\bscp\s+\S|\bsftp\s|\brsync\s[^\n]{0,200}?[^\s@]{1,64}@[^\s:]{1,255}:|(gethostbyname|getaddrinfo|dns\.resolver\.(query|resolve)|Resolve-DnsName|nslookup|\bdig)\b[^\n]{0,200}(\{|\+\s*\w|%s|\.format\(|\$\{?\w)|socket\.SOCK_RAW|hooks\.slack\.com|slack\.com/api/chat\.postMessage|\.webhook\.office\.com|outlook\.office\.com/webhook)", I), True),
    ("NET-DYNAMIC-HOST", "MEDIUM", "Network target is decoded at runtime (hides it from the domain inventory)",
     re.compile(r"((requests\.\w+|urlopen|httpx\.\w+|fetch|axios\.\w+|https?\.request|Invoke-WebRequest|Invoke-RestMethod)\s*\(\s*((base64\.)?b64decode|atob|bytes\.fromhex|(''|\"\")\.join|chr\(|String\.fromCharCode))", I), True),
    # Assembled URLs ('http://' + host) are everyday in normal code; LOW, so
    # the reviewer knows the inventory has a gap here.
    ("NET-CONCAT-HOST", "LOW", "Network target is assembled from parts: missing from the domain inventory",
     re.compile(r"(https?://[\"']\s*\+|https?://\{[a-z_]+\}\.)", I), True),
]

# ---------------------------------------------------------------------------
# Capabilities per script and dangerous combinations
# ---------------------------------------------------------------------------
# Why combinations? Single capabilities are mostly harmless: an API
# wrapper needs the network, a converter starts pandoc. It gets dangerous
# when one script joins a SOURCE of sensitive data (keys, home, screen)
# with a SINK to the outside (network). This does not replace tracing the
# data flow while reading, but says where to look first. Detection uses
# regexes rather than an AST so that it works the same for every language
# and nothing is parsed or executed.
CAPABILITIES = [
    ("NET", "network", re.compile(
        r"(requests\.(get|post|put|patch|delete|request|Session)|urllib\.request|urlopen|http\.client|\bsocket\.(socket|create_connection)|\baiohttp\b|\bhttpx\.|\bfetch\s*\(|XMLHttpRequest|\baxios\b|new\s+WebSocket|websockets?\.connect|\bsmtplib\b|\bftplib\b|\bparamiko\b|\bnodemailer\b|\bhttps?\.(get|request)\s*\(|\bnet\.(connect|createConnection)|Net\.WebClient|Invoke-(WebRequest|RestMethod)|(^|[\s;&|(`$])(iwr|irm|curl|wget|nc|ncat|scp|sftp)\s|DownloadString|gethostbyname|getaddrinfo|dns\.resolver|\bnslookup\b)", I | re.M)),
    ("SECRETS", "secrets/credentials", re.compile(
        r"(~/\.ssh|\.ssh/|\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials|\.netrc\b|\.git-credentials|\.config/gcloud|\.kube/config|\.docker/config\.json|\.azure/|gh/hosts\.yml|\.claude/\.credentials|\.npmrc|\.pypirc|\.vault-token|/proc/(self|\d+)/environ|_history\b|\bkeychain\b|find-(generic|internet)-password|CryptUnprotectData|Login Data|Local State|key[34]\.db|logins\.json|cookies\.sqlite|Local Storage[/\\]+leveldb|wallet\.dat|169\.254\.169\.254|metadata\.google\.internal|os\.environ\.(items|keys|values)\(\)|json\.dumps\(\s*(dict\()?\s*os\.environ|JSON\.stringify\(\s*process\.env\b|Object\.(keys|entries|values)\(\s*process\.env\s*\)|GetEnvironmentVariables\(\)|\bprintenv\b)", I)),
    ("ENV", "reads environment variables", re.compile(
        r"(os\.environ|os\.getenv|process\.env|\$env:|getenv\(|ENV\[)", I)),
    ("HOME", "home directory", re.compile(
        r"(expanduser\(|Path\.home\(\)|os\.homedir\(\)|\$HOME\b|~/|%USERPROFILE%|%APPDATA%|\$env:(USERPROFILE|APPDATA))", I)),
    ("FS_WALK", "walks directories", re.compile(
        r"(os\.walk\(|\.rglob\(|glob\.i?glob\([^\n]{0,200}recursive\s*=\s*True|os\.scandir\(|readdirSync\([^\n]{0,200}recursive|walkdir|Get-ChildItem[^\n]{0,200}-Recurse|\bfind\s+(/|~|\$HOME)\S*\s)", I)),
    ("CRYPTO", "encrypts", re.compile(
        r"(\bFernet\b|Crypto\.Cipher|Cryptodome|cryptography\.hazmat|\bAES\.new\b|createCipheriv|crypto\.subtle\.encrypt|\bopenssl\s+enc\b|\bChaCha20|nacl\.secret|\bgpg\s+(-c|--symmetric|--encrypt))", I)),
    ("DELETE", "deletes files", re.compile(
        r"(os\.(remove|unlink)\(|shutil\.rmtree|\.unlink\(|fs\.(unlink|rm|rmdir)(Sync)?\(|\brm\s+-|Remove-Item|\bshred\b|\bdel\s+/)", I)),
    ("EXEC", "starts processes/dynamic code", re.compile(
        r"(subprocess\.|os\.(system|popen|exec\w*|spawn\w*)\(|child_process|execSync|execFile|\bspawn\s*\(|Start-Process|Invoke-Expression|\biex\b|(?<![.\w])(exec|eval)\s*\(|new\s+Function\s*\(|pty\.spawn|Runtime\.getRuntime)", I)),
    ("DECODE", "decodes at runtime", re.compile(
        r"(b64decode|b32decode|a85decode|\batob\s*\(|bytes\.fromhex|unhexlify|codecs\.decode|zlib\.decompress|gzip\.decompress|lzma\.decompress|marshal\.loads|FromBase64String|Buffer\.from\([^)]{0,200}[\"'](base64|hex)[\"']|base64\s+(-d|--decode))", I)),
    ("SYSINFO", "collects system info", re.compile(
        r"(platform\.(node|uname)\(|socket\.gethostname|getpass\.getuser|os\.getlogin|os\.uname\(|os\.(hostname|userInfo|networkInterfaces)\(|(^\s*|[;&|`]\s*|\$\(\s*)(whoami|hostname|systeminfo|ipconfig|ifconfig)\b(?!\s*[=.:(\[,)])|(system|popen|run|call|check_output|Popen|execSync|exec)\(\s*\[?\s*[\"'](whoami|hostname|systeminfo|ipconfig|ifconfig)\b|uname\s+-a|\$env:(COMPUTERNAME|USERNAME))", I | re.M)),
    ("CAPTURE", "screen/keyboard/clipboard/camera", re.compile(
        r"(pynput|GetAsyncKeyState|SetWindowsHookEx|CGEventTapCreate|ImageGrab\.grab|pyautogui\.screenshot|\bmss\(\)|\bscreencapture\b|desktopCapturer|getDisplayMedia|pyperclip\.paste|\bpbpaste\b|Get-Clipboard|win32clipboard|cv2\.VideoCapture|getUserMedia|\bpyaudio\b)", I)),
]

NET_RX = dict((cid, rx) for cid, _, rx in CAPABILITIES)["NET"]

def lower_pattern(pattern):
    """Lower-cases all literals of a regex but leaves escapes such as \\S,
    \\W, \\B or \\x7f untouched (their upper-case letter has a meaning of
    its own). Reason: re.IGNORECASE makes Python's regex engine about four
    times slower. A lower-cased pattern on lower-cased text finds the same,
    only faster."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern[i] == "\\" and i + 1 < len(pattern):
            out.append(pattern[i:i + 2])
            i += 2
            continue
        out.append(pattern[i].lower())
        i += 1
    return "".join(out)


def prefilter_rx(rx):
    """Prefilter variant of a rule: lower-cased, without IGNORECASE, with
    MULTILINE for searching the whole file. Yields a superset of the
    per-line hits: ^/$ match at every line, \\s can at most reach across
    line ends in addition, and for rules without IGNORECASE (e.g.
    MAL-STEALER-BROWSER) the lower-cased variant is only more generous. So
    no hit is lost."""
    return re.compile(lower_pattern(rx.pattern), (rx.flags | re.M) & ~re.I)


# Prefilters of all rules and capabilities, compiled once at start.
RULES_PREFILTER = {rid: prefilter_rx(rx) for rid, _, _, rx, _ in RULES}
assert len(RULES_PREFILTER) == len(RULES), "rule IDs must be unique"
CAPS_FAST = [(cid, prefilter_rx(rx)) for cid, _, rx in CAPABILITIES]

# (required capabilities, severity, rule ID, description)
# Order: specific before general. Combinations that occur all the time in
# normal tooling code (network + process start) are only LOW so that the
# real patterns do not drown in noise; they still appear in the script
# inventory and are checked when the code is read in full.
COMBOS = [
    ({"SECRETS", "NET"}, "HIGH", "COMBO-EXFIL",
     "Reads secrets/credentials AND has network access: trace the data flow from source to sink"),
    ({"CAPTURE", "NET"}, "HIGH", "COMBO-SPY",
     "Captures screen/keyboard/clipboard AND has network access"),
    ({"FS_WALK", "CRYPTO", "DELETE"}, "HIGH", "COMBO-RANSOM",
     "Walks directories, encrypts AND deletes: ransomware pattern"),
    ({"FS_WALK", "HOME", "NET"}, "MEDIUM", "COMBO-COLLECT",
     "Walks the home directory AND has network access: what gets collected?"),
    ({"SYSINFO", "NET"}, "MEDIUM", "COMBO-BEACON",
     "Collects system info AND has network access (beacon/fingerprinting?)"),
    ({"DECODE", "EXEC"}, "LOW", "COMBO-DECODE-EXEC",
     "Decodes at runtime AND starts processes/code: check whether decoded data gets executed"),
    ({"NET", "EXEC"}, "LOW", "COMBO-FETCH-EXEC",
     "Network AND process start: check whether downloaded data gets executed"),
    ({"ENV", "NET"}, "LOW", "COMBO-ENV-NET",
     "Reads environment variables AND has network access: only its own key to its own provider?"),
]

# Allowed length of a code line before it counts as minified/obfuscated.
# Normal, readable scripts stay far below.
LONG_LINE = 3000
HEX_BLOB_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{200,}(?![0-9A-Fa-f])")
IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?![\d.])")

# HTML comments are not shown in rendered Markdown but are read by the
# model. Hence handled separately: always reported (LOW) and raised
# (MEDIUM) when they contain instruction vocabulary.
def iter_html_comments(text):
    """Yields (start, body, unclosed) for every HTML comment. Uses str.find
    rather than a regex, because <!--(.*?)--> turns quadratic with many
    unclosed comments (an attacker can stall the scanner for minutes that
    way). An unclosed comment is yielded as a finding of its own: in the
    rendering it hides the whole rest of the file."""
    pos = 0
    while True:
        start = text.find("<!--", pos)
        if start < 0:
            return
        end = text.find("-->", start + 4)
        if end < 0:
            yield start, text[start + 4:start + 4 + 2000], True
            return
        yield start, text[start + 4:end], False
        pos = end + 3


IMPERATIVE_RE = re.compile(r"\b(you must|you should|always|never|ignore|do not|don't|instruction|assistant|claude|ai model|send|run|execute|fetch)\b", I)

URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(:\d+)?", I)
B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/])")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def visible_snippet(text, limit=140):
    """Short excerpt for the report. Invisible characters are spelled out as
    <U+XXXX> so the report shows what is there."""
    out = []
    for ch in text.strip():
        cp = ord(ch)
        if ch in "\r\n":
            # Show line breaks (e.g. in HTML comments) as a space so the report
            # stays on one line and readable.
            out.append(" ")
        elif (cp < 32 and ch != "\t") or cp == 0xFEFF or cp >= 0xE0000 or any(
                lo <= cp <= hi for lo, hi, _ in INVISIBLE_RANGES) or cp == 0x200D:
            # Spell out only truly invisible characters; dashes, quotation marks
            # etc. stay readable as they are.
            out.append("<U+%04X>" % cp)
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def try_b64(blob):
    """Tries to decode a Base64 block. Returns the plain text if it is mostly
    printable (then it was hidden text and not a binary such as an embedded
    image)."""
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except Exception:
        return None
    if not raw:
        return None
    printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(raw) > 0.9:
        return raw.decode("ascii", "replace")
    return None


def binary_kind(raw):
    """Classifies decoded binary data by its first bytes.
    Returns ("EXEC", label) for programs, ("ARCHIVE", ...) for packed
    archives, ("BENIGN", None) for images/fonts/PDF, None if unknown.
    Background: a dropper likes to hide its actual program as a Base64 or
    hex string in the script and writes it to disk at runtime. try_b64()
    alone would miss that, because the result is not text."""
    if not raw:
        return None
    for magic, label in EXEC_MAGIC:
        if raw.startswith(magic):
            return ("EXEC", label)
    for magic, label in ARCHIVE_MAGIC:
        if raw.startswith(magic):
            return ("ARCHIVE", label)
    for magic in BENIGN_MAGIC:
        if raw.startswith(magic):
            return ("BENIGN", None)
    return None


def decode_b64_bytes(blob):
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except Exception:
        return b""


def line_of(text, needle):
    """Line number of the first occurrence (for findings from parsed JSON,
    which has no line numbers of its own). 0 if not found."""
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 0


# ---------------------------------------------------------------------------
# Manifests: code that runs automatically on install or start
# ---------------------------------------------------------------------------
# These files are not scripts, but they cause code to be executed or
# downloaded without further action. That is where most real supply-chain
# attacks start (npm postinstall, dependency from a foreign index, MCP
# server with @latest).
NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepack",
                 "postpack", "preuninstall", "uninstall", "postuninstall",
                 "prepublish")
RISKY_CMD_RE = re.compile(r"(curl|wget|https?://|node\s+-e|python3?\s+-c|eval|base64|\|\s*(ba)?sh|powershell|\biex\b)", re.I)
LAUNCHERS = {"npx", "uvx", "bunx", "pnpx", "pipx", "dlx", "docker", "podman", "deno"}


def json_or_none(text, rel, skill, findings):
    try:
        return json.loads(text)
    except ValueError:
        findings.append((skill, "LOW", "MANIFEST-PARSE", "JSON not parseable: check by hand", rel, 0, ""))
        return None


def check_package_json(text, rel, skill, findings):
    pkg = json_or_none(text, rel, skill, findings)
    if not isinstance(pkg, dict):
        return
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    for hook in NPM_LIFECYCLE:
        cmd = scripts.get(hook)
        if isinstance(cmd, str):
            sev = "HIGH" if RISKY_CMD_RE.search(cmd) else "MEDIUM"
            findings.append((skill, sev, "PKG-INSTALL-HOOK",
                             "npm lifecycle script '%s' runs automatically on npm install" % hook,
                             rel, line_of(text, '"%s"' % hook), visible_snippet(cmd)))
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = pkg.get(section)
        if not isinstance(deps, dict):
            continue
        for name, ver in deps.items():
            if not isinstance(ver, str):
                continue
            v = ver.strip()
            # Git, URL, local file or GitHub shorthand "user/repo": bypasses the
            # registry along with its malware checks and version pinning.
            if re.match(r"(git|github:|gitlab:|bitbucket:|https?:|file:|link:)", v) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", v):
                findings.append((skill, "MEDIUM", "PKG-DEP-SOURCE", "Dependency '%s' not from the npm registry: %s" % (name, v),
                                 rel, line_of(text, '"%s"' % name), ""))
            elif v in ("*", "latest", "") or v.startswith((">", "x")):
                findings.append((skill, "LOW", "PKG-DEP-UNPINNED", "Dependency '%s' without a pinned version (%s)" % (name, v or "empty"),
                                 rel, line_of(text, '"%s"' % name), ""))


def check_requirements(text, rel, skill, findings):
    unpinned = []
    for ln, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"(-i\s|--index-url|--extra-index-url|--trusted-host|-f\s|--find-links)", line):
            # Foreign or additional index: the classic route for "dependency
            # confusion" (same-named package with a higher version).
            findings.append((skill, "MEDIUM", "PIP-INDEX", "Additional/foreign package source", rel, ln, visible_snippet(line)))
        elif re.search(r"(git\+|https?://|file:|\s@\s)", line):
            findings.append((skill, "MEDIUM", "PIP-DEP-SOURCE", "Package from Git/URL instead of PyPI", rel, ln, visible_snippet(line)))
        elif line.startswith("-"):
            continue                      # -r, -c, -e . etc.
        elif "==" not in line and "@" not in line:
            unpinned.append(re.split(r"[<>=!~;\[\s]", line)[0])
    if unpinned:
        findings.append((skill, "LOW", "PIP-DEP-UNPINNED", "%d packages without an exact version: %s" % (len(unpinned), ", ".join(unpinned[:8])), rel, 0, ""))


def check_python_build(text, rel, skill, findings, name):
    # setup.py is code itself and runs in full on "pip install". A custom
    # install/develop/egg_info step is the typical place for malicious code
    # that only strikes during installation.
    if name == "setup.py":
        for ln, line in enumerate(text.splitlines(), 1):
            if re.search(r"(cmdclass|class\s+\w+\(\s*(install|develop|egg_info|build_py|sdist)\b)", line):
                findings.append((skill, "MEDIUM", "SETUP-HOOK", "setup.py replaces an install step (runs on pip install)", rel, ln, visible_snippet(line)))
    else:
        for ln, line in enumerate(text.splitlines(), 1):
            if re.search(r"(git\+|index-url|\[\[tool\.(uv|pdm|poetry)\.source\]\]|\[tool\.uv\.sources\]|https?://\S+\.(whl|tar\.gz|zip)|cmdclass)", line, re.I):
                findings.append((skill, "MEDIUM", "PY-DEP-SOURCE", "Dependency/build from a foreign source or a custom build step", rel, ln, visible_snippet(line)))


# Options of npx/uvx/docker whose next argument is a value.
# "--python 3.12" must not be read as the package "3.12". For
# -p/--package/--from the value IS the package being loaded.
LAUNCHER_PKG_OPTS = {"-p", "--package", "--from"}
LAUNCHER_VALUE_OPTS = {"--python", "--with", "--with-requirements", "--index", "--index-url",
                       "--extra-index-url", "--registry", "--cache", "-c", "--call", "--name",
                       "-e", "--env", "--env-file", "-v", "--volume", "--network", "--platform",
                       "-w", "--workdir", "--entrypoint", "-u", "--user", "--mount"}


def launcher_package(args):
    args = [a for a in args if isinstance(a, str)]
    i = 0
    while i < len(args):
        a = args[i]
        if a in LAUNCHER_PKG_OPTS and i + 1 < len(args):
            return args[i + 1]
        if a.split("=", 1)[0] in LAUNCHER_PKG_OPTS and "=" in a:
            return a.split("=", 1)[1]
        if a in LAUNCHER_VALUE_OPTS:
            i += 2
            continue
        if not a.startswith("-") and a not in ("run", "dlx", "exec", "x", "tool"):
            return a
        i += 1
    return ""


def mcp_pinned(cmd, args):
    """Is the package or image of a launcher (npx, uvx, docker ...) pinned to
    a fixed version? Unpinned, every start loads whatever code is published
    at that moment, i.e. unreviewed code."""
    base = os.path.basename(cmd)
    pkg = launcher_package(args)
    if not pkg:
        return True, ""
    if base in ("docker", "podman"):
        return ("@sha256:" in pkg or re.search(r":[\w.-]+$", pkg.split("/")[-1]) is not None) and not pkg.endswith(":latest"), pkg
    if pkg.endswith("@latest"):
        return False, pkg
    # npm: name@1.2.3 or @scope/name@1.2.3; Python: name==1.2.3
    return bool(re.search(r"(@\d|==\d|@v\d)", pkg)), pkg


def check_mcp_json(text, rel, skill, findings, scripts_inv):
    data = json_or_none(text, rel, skill, findings)
    if not isinstance(data, dict):
        return
    servers = data.get("mcpServers", data)
    if not isinstance(servers, dict):
        return
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        ln = line_of(text, '"%s"' % name)
        cmd = cfg.get("command") if isinstance(cfg.get("command"), str) else ""
        args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
        url = cfg.get("url") if isinstance(cfg.get("url"), str) else ""
        desc = url or " ".join([cmd] + [str(a) for a in args])
        findings.append((skill, "INFO", "MCP-SERVER", "MCP server '%s': %s" % (name, visible_snippet(desc, 160)), rel, ln, ""))
        scripts_inv[(skill, "%s#%s" % (rel, name))] = {"caps": ["MCP server"], "hosts": sorted({m.group(1).lower() for m in URL_RE.finditer(desc)})}
        if cmd and os.path.basename(cmd) in LAUNCHERS:
            ok, pkg = mcp_pinned(cmd, args)
            if not ok:
                findings.append((skill, "MEDIUM", "MCP-UNPINNED",
                                 "MCP server '%s' loads '%s' on every start without a pinned version" % (name, pkg), rel, ln, ""))
        if cmd and os.path.basename(cmd) in ("bash", "sh", "zsh", "powershell", "pwsh", "cmd", "cmd.exe"):
            findings.append((skill, "MEDIUM", "MCP-SHELL", "MCP server '%s' starts a shell: read the full command" % name, rel, ln, visible_snippet(desc)))


def check_hooks(data, text, rel, skill, findings):
    """Hooks run automatically on events (session start, before/after a tool
    call) without Claude or the user starting them deliberately. Every hook
    command is therefore reported individually and has to be read. Prompt
    hooks matter just as much: their text lands directly in the context."""
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return

    def walk(node, event):
        if isinstance(node, dict):
            for key in ("command", "prompt"):
                val = node.get(key)
                if isinstance(val, str):
                    rid = "HOOK-COMMAND" if key == "command" else "HOOK-PROMPT"
                    findings.append((skill, "MEDIUM", rid, "Hook '%s' runs automatically" % event, rel,
                                     line_of(text, val[:40]), visible_snippet(val)))
            for v in node.values():
                walk(v, event)
        elif isinstance(node, list):
            for v in node:
                walk(v, event)

    for event, entries in hooks.items():
        walk(entries, event)


def check_manifest(fpath, rel, skill, text, findings, scripts_inv):
    name = fpath.name
    if name == "package.json":
        check_package_json(text, rel, skill, findings)
    elif re.match(r"(requirements|constraints)[\w.-]*\.txt$", name, re.I):
        check_requirements(text, rel, skill, findings)
    elif name in ("setup.py", "pyproject.toml", "setup.cfg", "Pipfile"):
        check_python_build(text, rel, skill, findings, name)
    elif name in (".mcp.json", "mcp.json"):
        check_mcp_json(text, rel, skill, findings, scripts_inv)
    if name in ("hooks.json", "plugin.json", "settings.json", "settings.local.json"):
        data = json_or_none(text, rel, skill, findings)
        check_hooks(data, text, rel, skill, findings)
        # plugin.json may also give hooks/mcpServers inline or as a path.
        # Paths to unusual places are a hiding spot.
        if name == "plugin.json" and isinstance(data, dict):
            if isinstance(data.get("mcpServers"), dict):
                check_mcp_json(json.dumps(data["mcpServers"]), rel, skill, findings, scripts_inv)
            for key in ("hooks", "mcpServers", "commands", "agents"):
                val = data.get(key)
                if isinstance(val, str) and val not in ("./hooks/hooks.json", "./.mcp.json", "./commands", "./agents"):
                    findings.append((skill, "LOW", "PLUGIN-CUSTOM-PATH", "plugin.json points '%s' to %s: review that location too" % (key, val), rel, line_of(text, '"%s"' % key), ""))


def parse_frontmatter(text):
    """Minimal YAML frontmatter parser (top-level keys only). Deliberately no
    PyYAML: no third-party package, and yaml.load on foreign data would be
    a risk in itself."""
    m = re.match(r"\A﻿?---\r?\n(.*?)\r?\n---\s*(\r?\n|$)", text, re.S)
    if not m:
        return None
    fields = {}
    for line in m.group(1).splitlines():
        km = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line)
        if km:
            fields[km.group(1)] = km.group(2).strip().strip("\"'")
    return fields


def safe_extract(archive, dest, findings):
    """Extracts .zip/.skill safely. Checks for zip slip (../, absolute paths),
    symlinks inside the archive and zip bombs before anything is written."""
    with zipfile.ZipFile(archive) as zf:
        members = zf.infolist()
        if len(members) > ZIP_MAX_MEMBERS:
            raise ValueError("archive has too many entries (%d)" % len(members))
        total = sum(m.file_size for m in members)
        if total > ZIP_MAX_TOTAL:
            raise ValueError("archive too large when extracted (%d bytes): possible zip bomb" % total)
        for m in members:
            name = m.filename
            mode = (m.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                findings.append(("ARCHIVE", "HIGH", "ZIP-SYMLINK", "Symlink inside the archive", name, 0, name))
                continue
            p = Path(name)
            if p.is_absolute() or ".." in p.parts:
                findings.append(("ARCHIVE", "HIGH", "ZIP-SLIP", "Path leaves the target folder", name, 0, name))
                continue
            zf.extract(m, dest)


def skill_root_for(path, roots):
    """Assigns a file to the nearest skill folder (the one with SKILL.md)."""
    best = None
    for r in roots:
        try:
            path.relative_to(r)
        except ValueError:
            continue
        if best is None or len(str(r)) > len(str(best)):
            best = r
    return best


# ---------------------------------------------------------------------------
# Core: scan one file
# ---------------------------------------------------------------------------
def scan_file(fpath, rel, skill, findings, domains, scripts_inv):
    ext = fpath.suffix.lower()

    # Symlinks can point at ~/.ssh or similar and smuggle real secrets in
    # when the package is built. Never follow, always report.
    if fpath.is_symlink():
        findings.append((skill, "HIGH", "FS-SYMLINK", "Symlink -> %s" % os.readlink(fpath), rel, 0, ""))
        return

    st = fpath.stat()
    if st.st_mode & stat.S_IXUSR and ext not in CODE_EXT:
        findings.append((skill, "LOW", "FS-EXEC", "Executable bit on a non-script", rel, 0, ""))

    if ext in DANGEROUS_BINARY_EXT:
        findings.append((skill, "HIGH", "FS-BINARY", "Executable binary inside the skill", rel, 0, ""))
        return
    if ext in NESTED_ARCHIVE_EXT:
        findings.append((skill, "MEDIUM", "FS-NESTED-ARCHIVE",
                         "Nested archive: content NOT scanned, extract it separately or pass the archive to the scanner directly",
                         rel, 0, ""))
        return

    data = fpath.read_bytes()[:MAX_TEXT_BYTES]
    if ext in BENIGN_BINARY_EXT:
        # The extension alone is not enough: a "logo.png" that is really an
        # ELF or PE program is a classic disguise.
        kind = binary_kind(data[:16])
        if kind and kind[0] in ("EXEC", "ARCHIVE"):
            findings.append((skill, "HIGH" if kind[0] == "EXEC" else "MEDIUM", "FS-DISGUISED-BIN",
                             "File with extension '%s' is in fact: %s" % (ext, kind[1]), rel, 0, ""))
        return

    if b"\x00" in data[:8192]:
        # NUL bytes = binary with an unexpected extension (disguised as .md?)
        kind = binary_kind(data[:16])
        if kind and kind[0] == "EXEC":
            findings.append((skill, "HIGH", "FS-DISGUISED-BIN", "File with extension '%s' is in fact: %s" % (ext or "(none)", kind[1]), rel, 0, ""))
        else:
            findings.append((skill, "MEDIUM", "FS-UNKNOWN-BIN", "Binary file with text extension '%s'" % ext, rel, 0, ""))
        return
    text = data.decode("utf-8", "replace")

    # Code is not only recognised by its extension: a "helper" without one
    # but with "#!/bin/bash" on the first line is just as executable.
    has_shebang = text.startswith("#!")
    is_code = ext in CODE_EXT or fpath.name in CODE_NAMES or has_shebang
    if has_shebang and ext not in CODE_EXT and fpath.name not in CODE_NAMES:
        if ext in ("", ".bin"):
            findings.append((skill, "LOW", "FS-SHEBANG", "Script without an extension (shebang: %s)" % visible_snippet(text.splitlines()[0], 60), rel, 1, ""))
        else:
            findings.append((skill, "MEDIUM", "FS-SHEBANG-DISGUISE", "Script disguised as '%s' (shebang: %s)" % (ext, visible_snippet(text.splitlines()[0], 60)), rel, 1, ""))

    if is_code:
        findings.append((skill, "INFO", "CODE-FILE", "Contains executable code: read in full", rel, 0, ""))
    if st.st_size > LARGE_TEXT_WARN:
        findings.append((skill, "LOW", "FS-LARGE", "Very large text file (%d KB): good hiding place" % (st.st_size // 1024), rel, 0, ""))

    check_manifest(fpath, rel, skill, text, findings, scripts_inv)

    # 1) Invisible characters: summarised per file, otherwise a single hit
    #    with a thousand tag characters floods the report.
    inv = find_invisible(text)
    if inv:
        kinds = sorted({k for _, k in inv})
        lines = sorted({ln for ln, _ in inv})[:10]
        hidden = decode_tag_chars(text)
        detail = "%d characters (%s) on lines %s" % (len(inv), ", ".join(kinds), lines)
        if hidden.strip():
            detail += " | decoded tag text: " + visible_snippet(hidden, 200)
        findings.append((skill, "HIGH", "UNICODE-INVISIBLE", detail, rel, lines[0], ""))

    lines_list = text.splitlines()

    # 2) Line-based rules. Prefilter (see prefilter_rx): search the whole
    #    lower-cased file first and only on a hit check line by line with
    #    the exact rule. On large data files that saves most of the runtime.
    low = text.lower()
    for rid, sev, desc, rx, code_only in RULES:
        if code_only and not is_code:
            continue
        if not RULES_PREFILTER[rid].search(low):
            continue
        for ln, line in enumerate(lines_list, 1):
            if rx.search(line):
                findings.append((skill, sev, rid, desc, rel, ln, visible_snippet(line)))
    for ln, line in enumerate(lines_list, 1):
        mixed = mixed_script_words(line)
        if mixed:
            findings.append((skill, "MEDIUM", "HOMOGLYPH", "Mixed scripts in: %s" % ", ".join(mixed[:5]), rel, ln, visible_snippet(line)))
        for m in URL_RE.finditer(line):
            domains[skill].add(m.group(1).lower().rstrip("."))

    # 3) HTML comments (invisible when rendered)
    if ext in (".md", ".html", ".htm", ".txt", ""):
        for start, body, unclosed in iter_html_comments(text):
            ln = text.count("\n", 0, start) + 1
            if unclosed:
                findings.append((skill, "MEDIUM", "HTML-COMMENT-OPEN", "Unclosed HTML comment: the rest of the file is invisible when rendered", rel, ln, visible_snippet(body)))
                break
            sev = "MEDIUM" if IMPERATIVE_RE.search(body) else "LOW"
            findings.append((skill, sev, "HTML-COMMENT", "HTML comment (invisible when rendered)", rel, ln, visible_snippet(body)))

    # 4) Base64 blocks: report when they decode to text (hidden instruction)
    #    or to a program/archive (hidden payload). Embedded images
    #    (data:image/...;base64) are normal.
    for m in B64_RE.finditer(text):
        before = text[max(0, m.start() - 40): m.start()]
        if "base64," in before and ("data:image" in before or "data:font" in before or "data:application/font" in before):
            continue
        ln = text.count("\n", 0, m.start()) + 1
        decoded = try_b64(m.group(0))
        if decoded:
            sev = "HIGH" if re.search(r"(https?://|ignore|instruction|curl|password|token|system)", decoded, I) else "MEDIUM"
            findings.append((skill, sev, "OBF-BASE64", "Base64 block decodes to text", rel, ln, visible_snippet(decoded, 160)))
            continue
        kind = binary_kind(decode_b64_bytes(m.group(0)[:64]))
        if kind and kind[0] in ("EXEC", "ARCHIVE"):
            sev = "HIGH" if kind[0] == "EXEC" else "MEDIUM"
            findings.append((skill, sev, "OBF-PAYLOAD", "Base64 block contains %s (%d characters)" % (kind[1], len(m.group(0))), rel, ln, ""))
        elif kind is None and is_code and len(m.group(0)) >= 400 and ext != ".ipynb":
            findings.append((skill, "MEDIUM", "OBF-BLOB", "Large Base64 block in code decodes to unknown binary data (packed/encrypted payload?)", rel, ln, ""))

    if not is_code:
        return

    # 5) Code only: hex payloads, minified lines, capabilities.
    for m in HEX_BLOB_RE.finditer(text):
        kind = binary_kind(bytes.fromhex(m.group(0)[:64]))
        if kind and kind[0] in ("EXEC", "ARCHIVE"):
            ln = text.count("\n", 0, m.start()) + 1
            findings.append((skill, "HIGH" if kind[0] == "EXEC" else "MEDIUM", "OBF-PAYLOAD", "Hex block contains %s (%d characters)" % (kind[1], len(m.group(0))), rel, ln, ""))

    if ext != ".ipynb":
        for ln, line in enumerate(lines_list, 1):
            if len(line) > LONG_LINE:
                findings.append((skill, "LOW", "OBF-LONGLINE", "Very long code line (%d characters): minified or obfuscated? Is the source available?" % len(line), rel, ln, ""))
                break

    caps = [cid for cid, rx in CAPS_FAST if rx.search(low)]
    hosts = set()
    for line in lines_list:
        for m in URL_RE.finditer(line):
            hosts.add(m.group(1).lower().rstrip("."))
        # Bare IPs only on lines related to networking, otherwise version
        # numbers such as 1.2.3.4 end up in the inventory.
        if NET_RX.search(line):
            for m in IP_RE.finditer(line):
                if all(int(o) <= 255 for o in m.group(1).split(".")):
                    hosts.add(m.group(1))
    scripts_inv[(skill, rel)] = {"caps": caps, "hosts": sorted(hosts)}
    capset = set(caps)
    for need, sev, rid, desc in COMBOS:
        if need <= capset:
            findings.append((skill, sev, rid, desc, rel, 0, ""))


def check_frontmatter(skill_dir, skill, findings):
    """Checks the SKILL.md header: required fields and above all
    'allowed-tools', because a skill can use it to claim tool permissions
    without a prompt."""
    sk = skill_dir / "SKILL.md"
    if not sk.exists():
        return
    text = sk.read_text("utf-8", "replace")
    fm = parse_frontmatter(text)
    if fm is None:
        findings.append((skill, "MEDIUM", "FM-MISSING", "No YAML frontmatter in SKILL.md", "SKILL.md", 1, ""))
        return
    if not fm.get("name") or not fm.get("description"):
        findings.append((skill, "MEDIUM", "FM-FIELDS", "name/description missing", "SKILL.md", 1, ""))
    if fm.get("name") and fm["name"] != skill_dir.name:
        findings.append((skill, "LOW", "FM-NAME", "name '%s' != folder '%s'" % (fm["name"], skill_dir.name), "SKILL.md", 1, ""))
    if len(fm.get("description", "")) > 1024:
        findings.append((skill, "LOW", "FM-DESC-LONG", "description > 1024 characters (trigger hijacking possible)", "SKILL.md", 1, ""))
    for key in ("allowed-tools", "allowed_tools", "tools"):
        if key in fm:
            findings.append((skill, "MEDIUM", "FM-ALLOWED-TOOLS", "Claims tool permissions: %s=%s" % (key, fm[key] or "(list)"), "SKILL.md", 1, ""))


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
# Archive formats that are ZIP inside and can be extracted safely.
ZIP_BASED_EXT = (".zip", ".skill", ".plugin", ".whl", ".vsix", ".xpi", ".egg")


def scan_paths(paths):
    findings = []                 # (skill, severity, rule, description, file, line, snippet)
    domains = defaultdict(set)
    scripts_inv = {}              # (skill, file) -> {"caps": [...], "hosts": [...]}
    skills_seen = set()           # so skills without findings show up in the report too
    file_count = 0
    tmpdirs = []
    targets = []

    for p in paths:
        p = Path(p).resolve()
        if p.is_file() and p.suffix.lower() in ZIP_BASED_EXT and zipfile.is_zipfile(p):
            # Extract archives into their own empty temp folder so that foreign
            # files never end up next to our own scripts.
            td = Path(tempfile.mkdtemp(prefix="skillbouncer_"))
            tmpdirs.append(td)
            try:
                safe_extract(p, td, findings)
            except (ValueError, zipfile.BadZipFile, OSError) as e:
                findings.append(("(archive)", "HIGH", "ARCHIVE-ERROR", "Archive cannot be extracted safely: %s" % e, p.name, 0, ""))
            targets.append(td)
        else:
            targets.append(p)

    # Per target: (folder, nesting depth, display name of the archive).
    targets = [(t, 0, "") for t in targets]
    for base, depth, label in targets:
        # Skill folder = every folder with a SKILL.md. Do not follow symlinks.
        roots = sorted({f.parent for f in base.rglob("SKILL.md") if not f.is_symlink() and f.is_file()})
        for f in base.rglob("SKILL.md"):
            if f.is_dir() and not f.is_symlink():
                findings.append((f.parent.name, "HIGH", "FS-FAKE-SKILLMD", "SKILL.md is a directory, not a skill: disguise or an attack on the scanner", str(f.relative_to(base)), 0, ""))
        # Display name per root. For nested archives with their origin
        # ("plugin/vendor/x.skill!/x"), so it is clear where a finding is from.
        prefix = label + "!/" if label else ""
        root_names = {r: prefix + r.name for r in roots}
        for r in roots:
            skills_seen.add(root_names[r])
            try:
                check_frontmatter(r, root_names[r], findings)
            except Exception as e:  # noqa: BLE001
                findings.append((root_names[r], "HIGH", "SCAN-ERROR", "SKILL.md could not be checked (%s: %s)" % (type(e).__name__, e), "SKILL.md", 0, ""))
        # Plugin folder = folder with .claude-plugin/plugin.json. Files at plugin
        # level (.mcp.json, hooks/, package.json) belong to no skill but are
        # often the riskiest; they are therefore assigned to the plugin rather
        # than vanishing under "(outside skill)".
        plugin_roots = {}
        for pj in base.rglob(".claude-plugin/plugin.json"):
            if pj.is_symlink():
                continue
            proot = pj.parent.parent
            try:
                pname = json.loads(pj.read_text("utf-8", "replace")).get("name") or proot.name
            except (ValueError, AttributeError, OSError):
                pname = proot.name
            plugin_roots[proot] = "%splugin:%s" % (prefix, pname)
            skills_seen.add(plugin_roots[proot])
        all_roots = list(roots) + list(plugin_roots)
        for f in base.rglob("*"):
            if ".git" in f.parts or not (f.is_file() or f.is_symlink()):
                continue
            # Extract nested ZIP-based archives (.skill inside a plugin, .whl in
            # vendor/) safely and scan them too, rather than only reporting them
            # as "unchecked". At most two levels deep.
            if (not f.is_symlink() and f.suffix.lower() in ZIP_BASED_EXT and depth < 2
                    and zipfile.is_zipfile(f)):
                td = Path(tempfile.mkdtemp(prefix="skillbouncer_"))
                tmpdirs.append(td)
                inner_label = (label + "!/" if label else "") + str(f.relative_to(base))
                try:
                    safe_extract(f, td, findings)
                    targets.append((td, depth + 1, inner_label))
                    findings.append(("(archive)", "INFO", "ARCHIVE-SCANNED", "Nested archive extracted and scanned", inner_label, 0, ""))
                    file_count += 1
                    continue
                except (ValueError, zipfile.BadZipFile, OSError) as e:
                    findings.append(("(archive)", "MEDIUM", "FS-NESTED-ARCHIVE", "Archive could not be scanned: %s" % e, inner_label, 0, ""))
                    continue
            root = skill_root_for(f, all_roots)
            if root is None:
                skill = "(outside skill)"
            else:
                skill = plugin_roots.get(root) or root_names[root]
            rel = str(f.relative_to(root)) if root else str(f.relative_to(base))
            if label and root is None:
                rel = label + "!/" + rel
            file_count += 1
            try:
                scan_file(f, rel, skill, findings, domains, scripts_inv)
            except OSError as e:
                findings.append((skill, "LOW", "IO-ERROR", str(e), rel, 0, ""))
            except Exception as e:  # noqa: BLE001 - the scanner must never fail open
                findings.append((skill, "HIGH", "SCAN-ERROR", "File crashed the scanner (%s: %s): check by hand" % (type(e).__name__, e), rel, 0, ""))
    return findings, domains, skills_seen, file_count, tmpdirs, scripts_inv


def cleanup(tmpdirs):
    """Delete extracted archives again: foreign content should not linger in
    the temp folder."""
    for td in tmpdirs:
        shutil.rmtree(td, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Static security scanner for agent skills and plugins")
    ap.add_argument("paths", nargs="+", help="skill folder, folder of skills, or .zip/.skill/.plugin")
    ap.add_argument("--json", help="also write the findings as JSON")
    ap.add_argument("--min-severity", default="LOW", choices=SEVERITIES, help="lowest severity shown in the text output")
    ap.add_argument("--max-per-rule", type=int, default=8, help="max. lines per rule and skill in the text output")
    args = ap.parse_args()

    findings, domains, skills_seen, file_count, tmpdirs, scripts_inv = scan_paths(args.paths)
    cleanup(tmpdirs)

    # Summary per skill
    by_skill = defaultdict(list)
    for f in findings:
        by_skill[f[0]].append(f)
    all_skills = sorted(skills_seen | set(by_skill) | set(domains))

    worst_overall = "INFO"
    print("# skillbouncer scan report")
    print("Files scanned: %d | Skills: %d | Findings: %d\n" % (file_count, len(all_skills), len(findings)))
    print("## Overview (highest severity per skill)")
    for s in all_skills:
        sevs = [f[1] for f in by_skill.get(s, [])] or ["INFO"]
        worst = max(sevs, key=sev_rank)
        if sev_rank(worst) > sev_rank(worst_overall):
            worst_overall = worst
        counts = {k: sevs.count(k) for k in SEVERITIES if k in sevs and k != "INFO"}
        print("- %-28s %-6s %s" % (s, worst, " ".join("%s=%d" % kv for kv in counts.items())))

    print("\n## Findings from %s" % args.min_severity)
    for s in all_skills:
        items = [f for f in by_skill.get(s, []) if sev_rank(f[1]) >= sev_rank(args.min_severity)]
        if not items:
            continue
        print("\n### %s" % s)
        per_rule = defaultdict(int)
        for _, sev, rid, desc, rel, ln, snip in sorted(items, key=lambda x: (-sev_rank(x[1]), x[2], x[4], x[5])):
            per_rule[rid] += 1
            if per_rule[rid] > args.max_per_rule:
                if per_rule[rid] == args.max_per_rule + 1:
                    print("  - [%s] %s: ... further hits omitted (see JSON)" % (sev, rid))
                continue
            loc = "%s:%d" % (rel, ln) if ln else rel
            print("  - [%s] %s %s - %s%s" % (sev, rid, loc, desc, ("\n      > " + snip) if snip else ""))

    # Script inventory: starting point for step 5 (script analysis). Per code
    # file the detected capabilities and network targets. The aim is to
    # compare "purpose according to SKILL.md" with "what the code can do".
    if scripts_inv:
        labels = {cid: label for cid, label, _ in CAPABILITIES}
        print("\n## Script inventory (capabilities and network targets per code file)")
        for (s, rel) in sorted(scripts_inv):
            info = scripts_inv[(s, rel)]
            caps = ", ".join(labels.get(c, c) for c in info["caps"]) or "none detected"
            hosts = ", ".join(info["hosts"]) or "-"
            print("- %s/%s\n    Capabilities: %s\n    Targets: %s" % (s, rel, caps, hosts))

    print("\n## Domain inventory (all URLs per skill)")
    for s in all_skills:
        if domains.get(s):
            print("- %s: %s" % (s, ", ".join(sorted(domains[s]))))

    if args.json:
        Path(args.json).write_text(json.dumps({
            "files_scanned": file_count,
            "findings": [dict(zip(["skill", "severity", "rule", "description", "file", "line", "snippet"], f)) for f in findings],
            "domains": {k: sorted(v) for k, v in domains.items()},
            "scripts": [{"skill": s, "file": rel, "capabilities": v["caps"], "hosts": v["hosts"]}
                        for (s, rel), v in sorted(scripts_inv.items())],
        }, ensure_ascii=False, indent=2), "utf-8")

    sys.exit(2 if worst_overall == "HIGH" else 1 if worst_overall == "MEDIUM" else 0)


if __name__ == "__main__":
    main()
