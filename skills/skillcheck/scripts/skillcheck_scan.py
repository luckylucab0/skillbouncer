#!/usr/bin/env python3
"""
skillcheck_scan.py - statischer Sicherheits-Scanner fuer Agent-Skills.

Zweck
-----
Bevor ein fremder Skill (SKILL.md + references/ + scripts/ + assets/)
installiert wird, sucht dieses Skript nach typischen Mustern von
Prompt-Injection, Datenabfluss, Credential-Zugriff, gefaehrlichen
Shell-Befehlen und Verschleierung.

Warum statisch und ohne Abhaengigkeiten?
  * Das Skript liest den zu pruefenden Inhalt nur als Text. Es fuehrt
    nichts davon aus, importiert nichts daraus und greift nicht aufs
    Netz zu. So kann ein boesartiger Skill den Scanner selbst nicht
    angreifen.
  * Nur Python-Standardbibliothek, damit es in jeder Sandbox laeuft und
    keine fremden Pakete (Supply-Chain-Risiko) noetig sind.

Wichtig: Der Scanner ist ein Filter, kein Urteil. Er findet Kandidaten,
die ein Mensch bzw. Claude danach im Kontext lesen muss. Ein leerer
Report heisst "keine bekannten Muster", nicht "sicher". Semantische
Manipulation in gutem Englisch faengt nur das inhaltliche Lesen ab
(siehe SKILL.md, Schritt 4).

Skriptanalyse (seit 1.1.0)
--------------------------
Fuer Dateien mit ausfuehrbarem Code kommen drei Pruefungen dazu:
  * Malware-Regeln (MAL-*): Stealer, Keylogger, Ransomware, Miner,
    Abschalten von Virenschutz, Anti-Forensik, Nachladen von Code.
  * Faehigkeiten je Skript (Netz, Geheimnisse, Dateisuche, Prozesse ...)
    und deren Kombination (COMBO-*). Einzeln ist "liest ~/.aws" oder
    "macht HTTP-Requests" oft harmlos; beides im selben Skript ist das
    typische Muster eines Datenabflusses (Quelle -> Senke). Die Liste
    erscheint als "Skript-Inventar" im Report und dient als Startpunkt
    fuer das vollstaendige Lesen (references/skriptanalyse.md).
  * Manifeste, die beim Installieren oder Starten automatisch Code
    ausfuehren oder nachladen: package.json-Install-Hooks,
    requirements.txt mit Git-/URL-Quellen, .mcp.json, hooks.json.
Eingebettete Base64-Payloads werden auf Datei-Signaturen (PE, ELF,
Mach-O, ZIP ...) geprueft, weil versteckte Binaerdateien sonst als
"dekodiert nicht zu Text" durchrutschen wuerden.

Aufruf
------
    python3 -I skillcheck_scan.py PFAD [PFAD ...] [--json report.json]
                                  [--min-severity LOW] [--quiet-info]

PFAD darf sein: ein Ordner mit vielen Skills, ein einzelner Skill-Ordner,
oder ein ZIP-basiertes Archiv (.zip, .skill, .plugin, .whl ...; wird sicher
in ein Temp-Verzeichnis entpackt).

"-I" (isolated mode) ist Absicht: Python laedt dann keine Module aus dem
aktuellen Verzeichnis. Liegt im geprueften Repo z. B. eine praeparierte
"json.py", wuerde sie sonst beim "import json" ausgefuehrt.

Exit-Codes: 0 = nur LOW/INFO, 1 = mindestens MEDIUM, 2 = mindestens HIGH.
So laesst sich der Scanner auch in CI oder Skripten als Gate nutzen.
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
# Schweregrade
# ---------------------------------------------------------------------------
# Reihenfolge ist wichtig: der Index dient zum Filtern (--min-severity) und
# zum Bestimmen des Exit-Codes.
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH"]


def sev_rank(sev):
    return SEVERITIES.index(sev)


# ---------------------------------------------------------------------------
# Dateitypen
# ---------------------------------------------------------------------------
# Textdateien, deren Inhalt Claude potenziell liest oder ausfuehrt.
TEXT_EXT = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".csv", ".tsv", ".html", ".htm",
    ".xml", ".xsd", ".svg", ".css", ".py", ".js", ".mjs", ".cjs", ".ts", ".sh",
    ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".rb", ".pl", ".toml", ".ini",
    ".cfg", ".sql", ".jinja", ".j2", ".tpl", ".ipynb", "",
}
# Dateien mit ausfuehrbarem Code: muessen immer manuell gelesen werden,
# weil Claude sie laut SKILL.md womoeglich startet. Bewusst breit: auch
# Windows-Skriptformate (vbs, hta, wsf), die per Doppelklick laufen, und
# Quelltexte, die erst gebaut werden (go, rs, c), weil eine Anleitung
# "baue und starte das" sie genauso ausfuehrbar macht.
CODE_EXT = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash",
    ".zsh", ".fish", ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs",
    ".wsf", ".hta", ".rb", ".pl", ".php", ".lua", ".applescript",
    ".command", ".ipynb", ".go", ".rs", ".java", ".kt", ".swift", ".c",
    ".cpp", ".cs",
}
# Dateien ohne (eindeutige) Endung, die trotzdem Code ausfuehren, z. B.
# bei "make", "docker build" oder "pip install" (setup.py laeuft dabei).
CODE_NAMES = {
    "Makefile", "makefile", "GNUmakefile", "Dockerfile", "Containerfile",
    "justfile", "Justfile", "Rakefile", "Gemfile", "setup.py", "conftest.py",
}
# Harmlose Binaerformate (Schriften, Bilder, PDF-Vorlagen). Andere Binaries
# (exe, so, dll, jar, pyc ...) haben in einem Instruktions-Skill nichts zu
# suchen und werden hoch bewertet.
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
# Verschachtelte Archive: der Scanner entpackt sie nicht (Zip-Bomben,
# Endlosrekursion). Ihr Inhalt ist damit ungeprueft und muss separat
# entpackt und gescannt werden. Frueher stand .gz bei den harmlosen
# Formaten; ein .tar.gz kann aber genauso gut Skripte enthalten.
NESTED_ARCHIVE_EXT = {
    ".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".zst",
    ".skill", ".plugin", ".whl", ".egg", ".crx", ".xpi", ".vsix",
}
# Signaturen (Magic Bytes) ausfuehrbarer bzw. verpackter Inhalte. Damit
# erkennen wir Base64-Payloads im Code, die zu einer Binaerdatei
# dekodieren ("Dropper": Programm steckt als String im Skript).
EXEC_MAGIC = [
    (b"MZ", "Windows-Programm (PE/EXE/DLL)"),
    (b"\x7fELF", "Linux-Programm (ELF)"),
    (b"\xcf\xfa\xed\xfe", "macOS-Programm (Mach-O)"),
    (b"\xce\xfa\xed\xfe", "macOS-Programm (Mach-O)"),
    (b"\xca\xfe\xba\xbe", "Mach-O Universal / Java-Klasse"),
    (b"\x00asm", "WebAssembly-Modul"),
    (b"\xe3\x00\x00\x00", "Python-Bytecode (marshal)"),
]
# Archive: koennen Programme enthalten, kommen aber auch als Testdaten vor
# (z. B. ein Base64-ZIP in einem Unit-Test). Deshalb MEDIUM statt HIGH.
ARCHIVE_MAGIC = [
    (b"PK\x03\x04", "ZIP-Archiv (evtl. JAR/Wheel/Plugin)"),
    (b"\x1f\x8b", "GZIP-Archiv"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip-Archiv"),
    (b"Rar!", "RAR-Archiv"),
]
# Signaturen harmloser Medien: eingebettete Bilder/Schriften sind normal.
BENIGN_MAGIC = [
    b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"%PDF", b"RIFF", b"wOFF", b"wOF2",
    b"\x00\x01\x00\x00", b"OTTO", b"ID3", b"<svg", b"<?xml", b"\x00\x00\x01\x00",
]

MAX_TEXT_BYTES = 5_000_000        # groessere Textdateien nur teilweise lesen
LARGE_TEXT_WARN = 1_000_000       # sehr grosse Referenzdateien = gutes Versteck
ZIP_MAX_TOTAL = 300_000_000       # Schutz vor Zip-Bomben beim Entpacken
ZIP_MAX_MEMBERS = 20_000

# ---------------------------------------------------------------------------
# Unsichtbare / richtungsverändernde Unicode-Zeichen
# ---------------------------------------------------------------------------
# Damit lassen sich Anweisungen verstecken, die im Editor unsichtbar sind,
# vom Modell aber gelesen werden ("ASCII smuggling" ueber Tag-Zeichen,
# Trojan-Source ueber Bidi-Overrides, Steganografie ueber Variation
# Selectors Supplement).
INVISIBLE_RANGES = [
    (0x200B, 0x200C, "Zero-Width Space/Non-Joiner"),
    (0x200E, 0x200F, "LTR/RTL Mark"),
    (0x202A, 0x202E, "Bidi-Embedding/Override"),
    (0x2060, 0x2064, "Word Joiner/unsichtbare Operatoren"),
    (0x2066, 0x2069, "Bidi-Isolate"),
    (0x180E, 0x180E, "Mongolian Vowel Separator"),
    (0xE0000, 0xE007F, "Unicode-Tag-Zeichen (ASCII smuggling)"),
    (0xE0100, 0xE01EF, "Variation Selector Supplement (Steganografie)"),
]


def is_emoji_like(ch):
    """Grobe Emoji-Erkennung, damit ZWJ (U+200D) in Emoji-Sequenzen wie
    Familien-Emojis nicht als Fund gemeldet wird."""
    cp = ord(ch)
    return (0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF
            or 0x2300 <= cp <= 0x23FF or cp in (0xFE0F, 0x2640, 0x2642))


def find_invisible(text):
    """Liefert Liste (zeilennummer, beschreibung) fuer versteckte Zeichen."""
    hits = []
    line = 1
    for i, ch in enumerate(text):
        if ch == "\n":
            line += 1
            continue
        cp = ord(ch)
        if cp == 0x200D:
            # ZWJ zwischen zwei Emoji ist normal (z. B. Hautfarben-Sequenzen).
            prev_ch = text[i - 1] if i > 0 else ""
            next_ch = text[i + 1] if i + 1 < len(text) else ""
            if prev_ch and next_ch and is_emoji_like(prev_ch) and is_emoji_like(next_ch):
                continue
            hits.append((line, "Zero-Width Joiner ausserhalb Emoji"))
            continue
        if cp == 0xFEFF and i > 0:
            # BOM am Dateianfang ist normal, mitten im Text nicht.
            hits.append((line, "BOM/Zero-Width No-Break Space im Text"))
            continue
        for lo, hi, label in INVISIBLE_RANGES:
            if lo <= cp <= hi:
                hits.append((line, label))
                break
    return hits


def decode_tag_chars(text):
    """Unicode-Tag-Zeichen (U+E0020..U+E007E) spiegeln ASCII. Wenn ein
    Skill sie enthaelt, zeigen wir den versteckten Klartext gleich mit an,
    damit man sieht, was geschmuggelt werden sollte."""
    out = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    return out


# ---------------------------------------------------------------------------
# Homoglyphen: lateinische und kyrillische/griechische Buchstaben im selben
# Wort. Typisch fuer gefaelschte Domains ("аnthropic.com" mit kyrillischem а)
# oder um Wortfilter zu umgehen.
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
# Regelwerk fuer Textmuster
# ---------------------------------------------------------------------------
# Jede Regel: (id, severity, beschreibung, regex, nur_in_code)
# nur_in_code=True heisst: Regel gilt nur fuer Skript-Dateien, weil das
# Muster in Prosa (z. B. "requests" als Wort) zu viele Fehlalarme gaebe.
#
# Die Regeln sind bewusst eher breit. Ziel ist hohe Trefferquote; das
# Aussortieren von Fehlalarmen passiert beim Triage-Schritt im Kontext.
I = re.IGNORECASE
RULES = [
    # --- Prompt-Injection: Versuche, System-/Nutzerinstruktionen auszuhebeln
    ("INJ-OVERRIDE", "HIGH", "Aufforderung, bisherige Instruktionen zu ignorieren",
     re.compile(r"\b(ignore|disregard|forget|override|bypass)\b.{0,25}\b(all|any|the|your|previous|prior|above|earlier|system|safety|other)\b.{0,25}\b(instructions?|rules|prompts?|guidelines|polic(y|ies)|guardrails|restrictions)\b", I), False),
    ("INJ-OVERRIDE-DE", "HIGH", "Aufforderung (DE), Anweisungen zu ignorieren",
     re.compile(r"\b(ignorier|vergiss|missacht|umgeh)\w*\b.{0,30}\b(anweisung|regel|vorgabe|richtlinie|sicherheit)\w*", I), False),
    ("INJ-ROLE", "MEDIUM", "Rollenwechsel / Jailbreak-Formulierung",
     re.compile(r"\b(you are now|from now on you are|new (system )?instructions|developer mode|jailbreak|DAN mode|act as (an? )?unrestricted|no longer bound)\b", I), False),
    ("INJ-SPOOF", "MEDIUM", "Gefaelschte System-/Turn-Marker",
     re.compile(r"(<\|im_start\|>|<\|system\|>|</?system>|\[SYSTEM\]|\[INST\]|^\s*(Human|Assistant|System)\s*:\s)", I | re.M), False),
    ("INJ-AUTHORITY", "MEDIUM", "Behauptete Autoritaet / Vorab-Freigabe",
     re.compile(r"\b(anthropic (has )?(authori[sz]ed|requires|approved)|pre-?authori[sz]ed|the user (has )?already (approved|consented|authori[sz]ed)|official instruction from|admin override)\b", I), False),
    ("DECEPT-HIDE", "HIGH", "Verheimlichen gegenueber dem Nutzer",
     re.compile(r"\b(do not|don't|never)\s+(tell|inform|mention|reveal|show|disclose|notify)\b.{0,30}\b(the user|users|anyone|this)\b|\bwithout (telling|informing|notifying|alerting) (the )?user\b|\bhide (this|it|these) from\b|\bkeep (this|it) (a )?secret\b", I), False),
    ("DECEPT-HIDE-DE", "HIGH", "Verheimlichen (DE)",
     re.compile(r"\b(ohne (den|die) (nutzer|benutzer|user)\w* zu (informieren|fragen|benachrichtigen)|sag\w* (dem|der) (nutzer|benutzer|user)\w* nicht|verheimlich\w*)\b", I), False),
    ("DECEPT-SILENT", "MEDIUM", "Stille Aktion (silently/quietly + Aktion)",
     re.compile(r"\b(silently|quietly|secretly|covertly|in the background)\b.{0,20}\b(send|upload|post|run|execute|install|delete|forward|copy|exfiltrate|share)\b", I), False),

    # --- Datenabfluss
    ("EXFIL-SERVICE", "HIGH", "Bekannter Exfiltrations-/Tunnel-/Paste-Dienst",
     re.compile(r"(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|trycloudflare\.com|serveo\.net|localtunnel|loca\.lt|pastebin\.com|paste\.ee|hastebin|transfer\.sh|file\.io|0x0\.st|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator|canarytokens|beeceptor|hookbin)", I), False),
    ("EXFIL-IMG", "HIGH", "Markdown-Bild/Link mit dynamischen Platzhaltern (klassischer Exfil-Kanal)",
     re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]*(\{\{|\$\{|\$[A-Z_]{3,}|<[a-z_]+>|\{[a-z_]+\})", I), False),
    ("EXFIL-PARAM", "MEDIUM", "URL transportiert sensible Daten als Parameter",
     re.compile(r"https?://[^\s)\"'>]*[?&](data|payload|conversation|chat|history|token|key|secret|password|pwd|cookie|session|email|content)=", I), False),
    ("EXFIL-SEND", "MEDIUM", "Anweisung, Gespraechs-/Nutzerdaten nach aussen zu senden",
     re.compile(r"\b(send|post|upload|forward|transmit|submit)\b.{0,40}\b(conversation|chat history|transcript|user'?s? (data|files|messages|credentials|emails?)|system prompt|environment variables|api keys?)\b.{0,40}\b(to|via)\b", I), False),
    ("NET-RAW-IP", "MEDIUM", "URL auf nackte IP-Adresse",
     re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?", I), False),
    ("NET-SHORTENER", "LOW", "URL-Kuerzer verschleiert das Ziel",
     re.compile(r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|rb\.gy|cutt\.ly|ow\.ly|shorturl\.at|tiny\.cc)/", I), False),

    # --- Zugriff auf Geheimnisse
    # "Login Data" (Chrome-Passwortdatenbank) steht jetzt in MAL-STEALER-BROWSER
    # mit Pfadtrenner davor; ohne Gross-/Kleinschreibung hat es frueher auch
    # normale Prosa wie "login data is stored" als HIGH gemeldet.
    ("SECRET-PATH", "HIGH", "Zugriff auf Schluessel-/Credential-Speicher",
     re.compile(r"(~/\.ssh|\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials|\.netrc\b|\.git-credentials|/etc/(passwd|shadow)|\bkeychain\b|\.config/gcloud|\.kube/config|\.docker/config\.json|wallet\.dat|\.npmrc|\.pypirc|\.azure/|gh/hosts\.yml|\.claude/\.credentials|\.vault-token|\.terraform\.d/credentials|/proc/(self|\d+|\*)/environ|\.(bash|zsh)_history)", I), False),
    ("SECRET-CLOUD-META", "HIGH", "Abfrage des Cloud-Metadatendienstes (liefert Instanz-Zugangsdaten)",
     re.compile(r"(169\.254\.169\.254|169\.254\.170\.2|fd00:ec2::254|metadata\.google\.internal|metadata\.azure\.com|/latest/meta-data|/computeMetadata/)", I), False),
    # Eine einzelne, benannte Variable (os.getenv("FOO_API_KEY")) ist normal.
    # Auffaellig ist, wenn ein Skript ALLE Variablen einsammelt: dort stehen
    # in Sandboxen oft Tokens, die der Skill gar nicht braucht.
    # os.environ.copy() / {**os.environ} fehlen absichtlich: damit wird meist
    # nur die Umgebung an einen Unterprozess weitergereicht.
    ("SECRET-ENV-DUMP", "MEDIUM", "Liest alle Umgebungsvariablen auf einmal (statt einer benannten)",
     re.compile(r"(os\.environ\.(items|keys|values)\(\)|json\.dumps\(\s*(dict\()?\s*os\.environ|str\(\s*os\.environ\s*\)|for\s+\w+(\s*,\s*\w+)?\s+in\s+os\.environ\b|JSON\.stringify\(\s*process\.env\b|Object\.(keys|entries|values)\(\s*process\.env\s*\)|GetEnvironmentVariables\(\))", I), True),
    ("SECRET-ENV", "MEDIUM", "Umgebungsvariablen/.env auslesen",
     re.compile(r"(\bprintenv\b|\benv\s*\||\bcat\s+[^\n]*\.env\b|\bread (the )?\.env\b|\bset\s*>|Get-ChildItem\s+env:)", I), False),
    ("SECRET-ASK", "LOW", "Fragt nach Passwort/API-Key/Token",
     re.compile(r"\b(ask|prompt|request)\b.{0,30}\b(the user|them|user)\b.{0,30}\b(password|passphrase|api[ _-]?key|access token|secret key|private key|seed phrase|2fa|otp)\b", I), False),

    # --- Gefaehrliche Shell-Muster
    ("SHELL-PIPE", "HIGH", "Download direkt in Shell ausfuehren",
     re.compile(r"(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(sudo\s+)?((ba|z|da)?sh|iex|python3?|node|perl|ruby)\b|\biex\s*\(|Invoke-Expression|powershell[^\n]*-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh|eval\s+\"?\$\((curl|wget)", I), False),
    ("SHELL-REVERSE", "HIGH", "Reverse-Shell / Netzwerk-Backdoor",
     re.compile(r"(/dev/tcp/|\bnc\s+(-[a-z]*e|-c)\b|\bncat\b.*-e|\bmkfifo\b|\bsocat\b.*exec|bash\s+-i\s+>&)", I), False),
    ("SHELL-DESTRUCT", "HIGH", "Destruktiver Befehl",
     re.compile(r"(\brm\s+-[a-z]*r[a-z]*f?\s+(/|~|\$HOME|\*)(\s|$)|\bmkfs\.|\bdd\s+if=.*of=/dev/|:\(\)\s*\{\s*:\|:&\s*\};:|\bchmod\s+-R\s+777\s+/)", I), False),
    ("SHELL-PERSIST", "HIGH", "Persistenz (Autostart, Cron, Shell-Profile)",
     re.compile(r"(\bcrontab\b|\blaunchctl\s+load\b|systemctl\s+enable\b|>>\s*~?/?\.?(bash|zsh)rc\b|>>\s*~/\.profile|\bschtasks\b|HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run)", I), False),
    ("SHELL-SUDO", "MEDIUM", "Erhoehte Rechte (sudo/runas)",
     re.compile(r"(^|\s|`)(sudo|runas|doas)\s+\S", I), False),
    ("SHELL-INSTALL", "MEDIUM", "Paketinstallation (Supply-Chain-Risiko, Herkunft pruefen)",
     re.compile(r"\b(pip3?\s+install|npm\s+(install|i)\s|npx\s+-?[a-z@]|pnpm\s+(add|dlx)|yarn\s+(add|dlx)|bunx\s|gem\s+install|go\s+install|cargo\s+install|brew\s+install|uvx\s|pipx\s+run)", I), False),
    ("SHELL-POST", "LOW", "HTTP-POST per Kommandozeile",
     re.compile(r"\bcurl\b[^\n]*(-X\s*POST|--data|\s-d\s|-F\s|--upload-file)", I), False),

    # --- Verschleierung (Code)
    ("OBF-DECODE", "MEDIUM", "Laufzeit-Dekodierung/dynamische Ausfuehrung",
     # (?<![.\w]) schliesst Methodenaufrufe wie regex.exec(...) oder
     # re.compile(...) aus. Die sind harmlos und in JS/Python allgegenwaertig;
     # gefaehrlich sind nur die freistehenden Builtins exec()/eval()/compile().
     re.compile(r"(\batob\s*\(|String\.fromCharCode|base64\.b64decode|codecs\.decode|bytes\.fromhex|(?<![.\w])exec\s*\(|(?<![.\w])eval\s*\(|(?<![.\w])compile\s*\(|__import__\s*\(|marshal\.loads|pickle\.loads|new Function\s*\()", I), True),
    ("OBF-HEX", "MEDIUM", "Lange Hex-/Escape-Sequenz",
     re.compile(r"(\\x[0-9a-f]{2}){12,}|(\\u[0-9a-f]{4}){12,}", I), False),

    # --- Netzwerk / Prozesse in Skripten: kein Fund per se, aber Inventar
    ("CODE-NET", "LOW", "Skript macht Netzwerkzugriffe",
     re.compile(r"\b(requests\.(get|post|put|delete|request)|urllib\.request|urlopen|http\.client|socket\.socket|aiohttp|httpx\.|fetch\s*\(|XMLHttpRequest|axios\.|WebSocket\s*\()", I), True),
    ("CODE-PROC", "LOW", "Skript startet Prozesse",
     re.compile(r"\b(subprocess\.|os\.system|os\.popen|child_process|execSync|spawn\s*\(|Runtime\.getRuntime)", I), True),
    ("CODE-HOME", "MEDIUM", "Skript liest im Home-Verzeichnis",
     re.compile(r"(os\.path\.expanduser\(|Path\.home\(\)|os\.homedir\(\)|\$HOME/|%USERPROFILE%)", I), True),

    # --- Manipulation von Gedaechtnis/Konfiguration
    ("PERSIST-MEMORY", "MEDIUM", "Schreibt in Gedaechtnis/Konfiguration des Assistenten",
     re.compile(r"(\bCLAUDE\.md\b|\bmemory_(write|append|str_replace)\b|\bsave (this|these|it) (to|in) (your )?memory\b|~/\.claude\b|\.claude/settings|\badd (this )?to (your|the) system prompt\b|\bupdate (the user'?s|your) preferences\b)", I), False),
    ("AUTONOMY", "MEDIUM", "Handlung ohne Rueckfrage beim Nutzer",
     re.compile(r"\b(without (asking|confirmation|approval|user approval|permission)|do not ask (for )?(permission|confirmation|approval)|never ask (for )?(permission|confirmation)|automatically (send|post|publish|purchase|buy|pay|delete|submit))\b", I), False),

    # --- Versteckte Inhalte in Markdown/HTML
    ("HIDDEN-HTML", "MEDIUM", "Per CSS versteckter HTML-Inhalt",
     re.compile(r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0[;\"']|color\s*:\s*(#fff(fff)?|white)\s*;\s*background\s*:\s*(#fff(fff)?|white))", I), False),

    # =======================================================================
    # Malware-Muster in Skripten (seit 1.1.0)
    # =======================================================================
    # Gruppiert nach dem, was Schadcode typischerweise tut. Die meisten
    # Regeln gelten auch fuer Prosa (nur_in_code=False), weil eine SKILL.md
    # Claude ebenso anweisen kann, den Befehl selbst auszufuehren. Regeln mit
    # haeufigen Woertern laufen nur ueber Code, sonst flutet Prosa den Report.

    # --- Nachladen und Ausfuehren ("Dropper"/"Loader")
    ("MAL-DOWNLOAD-EXEC", "HIGH", "Laedt Code aus dem Netz und fuehrt ihn aus",
     re.compile(r"((?<![.\w])(exec|eval)\s*\(\s*(await\s+)?(requests\.\w+|urlopen|urllib\.request\.urlopen|httpx\.\w+|fetch|https?\.get|axios\.get)\s*\(|(bash|sh|zsh|source)\s+<\(\s*(curl|wget)|(python3?|node|perl|ruby|php)\s+-[ce]\s+[\"']?\$\((curl|wget)|sh\s+-c\s+[\"']?\$\((curl|wget)|DownloadString\(|DownloadFile\([^\n]{0,200}\.(exe|ps1|bat|dll|scr|vbs|msi)|Start-BitsTransfer|certutil(\.exe)?\s[^\n]{0,200}-urlcache|bitsadmin\s+/transfer|mshta(\.exe)?\s+[\"']?(https?:|javascript:|vbscript:)|regsvr32[^\n]{0,200}/i:\s*https?:|rundll32[^\n]{0,200}(javascript:|https?:)|(urlretrieve|wget|curl)\b[^\n]{0,200}&&\s*(chmod\s+\+x|\./))", I), False),
    ("MAL-DECODE-EXEC", "HIGH", "Dekodiert Daten und fuehrt sie direkt aus",
     re.compile(r"((?<![.\w])(exec|eval|compile)\s*\(\s*([\w.]*\.)?(b64decode|b32decode|a85decode|decompress|loads|fromhex|atob|unhexlify)\s*\(|(?<![.\w])(exec|eval)\s*\(\s*[\"'][^\"']*[\"']\s*\[::-1\]|(?<![.\w])(exec|eval)\s*\(\s*(bytes|bytearray)\(|(?<![.\w])(exec|eval)\s*\(\s*(''|\"\")\.join|(?<![.\w])eval\s*\(\s*Buffer\.from\(|new\s+Function\s*\(\s*atob\(|FromBase64String[^\n]{0,200}(\biex\b|Invoke-Expression)|(\biex\b|Invoke-Expression)[^\n]{0,200}FromBase64String)", I), True),
    ("OBF-INDIRECT", "MEDIUM", "Indirekter Zugriff auf Builtins (umgeht Mustersuche nach exec/eval)",
     re.compile(r"(getattr\(\s*(__builtins__|builtins|globals\(\))\s*,|__builtins__\s*\.\s*__dict__|__builtins__\s*\[|globals\(\)\s*\[\s*[\"']|[\"']ex[\"']\s*\+\s*[\"']ec[\"']|[\"']ev[\"']\s*\+\s*[\"']al[\"']|[\"']sys[\"']\s*\+\s*[\"']tem[\"']|\[\s*[\"']constructor[\"']\s*\]\s*\(|coding[:=]\s*(rot.?13|unicode.escape|raw.unicode.escape|utf.?7))", I), True),

    # --- Informationsdiebstahl ("Stealer")
    # Case-sensitiv und mit Pfadtrenner davor: "Local State" oder "Web Data"
    # sind sonst normale Woerter in UI-Doku.
    ("MAL-STEALER-BROWSER", "HIGH", "Zugriff auf Browser-Profile (gespeicherte Passwoerter, Cookies, Schluessel)",
     re.compile(r"([/\\\"']Login Data\b|[/\\\"']Local State\b|[/\\\"']Web Data\b|\bkey[34]\.db\b|\blogins\.json\b|cookies\.sqlite|\bCryptUnprotectData\b|Mozilla[/\\]+Firefox[/\\]+Profiles|\.mozilla/firefox|Google[/\\]+Chrome[/\\]+User Data|Application Support/Google/Chrome|BraveSoftware[/\\]+Brave-Browser|Microsoft[/\\]+Edge[/\\]+User Data|find-(generic|internet)-password|security\s+dump-keychain|browser_cookie3|\bpycookiecheat\b)"), False),
    ("MAL-STEALER-APPS", "HIGH", "Zugriff auf Sitzungs-Token von Apps oder Krypto-Wallets",
     re.compile(r"(discord(canary|ptb)?[/\\]+Local Storage|Local Storage[/\\]+leveldb|Telegram Desktop[/\\]+tdata|[/\\]tdata[/\\]|Slack[/\\]+(Cookies|storage)|Teams[/\\]+(Cookies|Local Storage)|[/\\](Exodus|Electrum|Atomic|Armory|Ethereum|Bitcoin)[/\\]+(wallets?|keystore|exodus\.wallet)|nkbihfbeogaeaoehlefnkodbefgpgknn|Local Extension Settings)", I), False),
    ("MAL-KEYLOG", "HIGH", "Tastatureingaben mitschneiden (Keylogger)",
     re.compile(r"(pynput\.keyboard|\bkeyboard\.(on_press|on_release|hook|record)\b|\bGetAsyncKeyState\b|\bSetWindowsHookEx\w*|\bWH_KEYBOARD(_LL)?\b|CGEventTapCreate|xinput\s+test\b|/dev/input/event|\biohook\b|node-global-key-listener)", I), True),
    ("MAL-SPY-CAPTURE", "MEDIUM", "Bildschirm, Zwischenablage, Kamera oder Mikrofon auslesen",
     re.compile(r"(ImageGrab\.grab|pyautogui\.screenshot|\bmss\(\)|\bscreencapture\b|\bscrot\b|desktopCapturer|getDisplayMedia|pyperclip\.paste|\bpbpaste\b|xclip\s[^\n]{0,200}-o\b|xsel\s+(-o|--output|-b)\b|Get-Clipboard|clipboard\.read(Text)?\(|win32clipboard|cv2\.VideoCapture|getUserMedia|\bpyaudio\b|sounddevice\.rec|\bimagesnap\b|\bffmpeg\b[^\n]{0,200}-f\s+(avfoundation|dshow|v4l2|alsa|pulse|gdigrab|x11grab))", I), True),
    ("MAL-RECON", "MEDIUM", "Erkundung von System, Netz oder Domaene",
     re.compile(r"(whoami\s+/(all|priv|groups)|\bnet\s+(user|group|localgroup|view|share)\b|\bsysteminfo\b|ipconfig\s+/all|\barp\s+-a\b|\bnltest\b|Get-AD(User|Computer|Group)|\bnmap\b|\bmasscan\b|\bnetstat\s+-[a-z]*a|Get-NetTCPConnection|ifconfig\s+-a\b)", I), True),

    # --- Erpressung, Zerstoerung, Ressourcenmissbrauch
    ("MAL-RANSOM", "HIGH", "Ransomware-/Wiper-Merkmal (Schattenkopien, Loesegeld, Umbenennen in .locked)",
     re.compile(r"(vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit[^\n]{0,200}recoveryenabled\s+no|wbadmin\s+delete|cipher(\.exe)?\s+/w:|your (files|data|documents) (have|has) been encrypted|decrypt\w*\s[^\n]{0,60}(bitcoin|\bbtc\b|monero|\bxmr\b|ransom)|\+\s*[\"']\.(locked|encrypted|crypted|crypt|enc|pay|ransom)[\"'])", I), False),
    ("MAL-MINER", "HIGH", "Krypto-Mining",
     re.compile(r"(stratum\+(tcp|ssl|tls)://|\bxmrig\b|\bxmr-stak\b|\bcpuminer\b|\bminerd\b|\bnbminer\b|\bethminer\b|\bcoinhive\b|\bcryptonight\b|\bnicehash\b|(minexmr|supportxmr|nanopool|2miners|f2pool|hashvault|moneroocean)\.\w+|--donate-level)", I), False),

    # --- Schutzmechanismen aushebeln und Spuren verwischen
    ("MAL-EVASION", "HIGH", "Virenschutz, Systemschutz, Firewall oder Protokollierung abschalten",
     re.compile(r"(Set-MpPreference\s[^\n]{0,200}-Disable|Add-MpPreference\s[^\n]{0,200}-Exclusion|DisableRealtimeMonitoring|DisableAntiSpyware|AmsiUtils|amsiInitFailed|AmsiScanBuffer|spctl\s+--master-disable|csrutil\s+disable|setenforce\s+0|\bufw\s+disable|systemctl\s+(stop|disable|mask)\s+(auditd|rsyslog|apparmor|firewalld|falcon|wazuh|osquery)|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off|EtwEventWrite)", I), False),
    ("MAL-EVASION-SOFT", "MEDIUM", "Unauffaellig starten (verstecktes Fenster, Gatekeeper/ExecutionPolicy umgehen)",
     re.compile(r"(-ExecutionPolicy\s+(Bypass|Unrestricted)|-ep\s+bypass\b|-WindowStyle\s+Hidden|-w\s+hidden\b|CREATE_NO_WINDOW|DETACHED_PROCESS|\bpythonw(\.exe)?\b|xattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine|\b[wc]script(\.exe)?\s)", I), False),
    # Hintergrundprozesse sind fuer lokale Server normal (nohup + disown),
    # ueberleben aber die Sitzung. Deshalb nur LOW und nur in Code: im
    # Skript-Inventar sichtbar, ohne die Triage zu fluten.
    ("CODE-BACKGROUND", "LOW", "Startet abgekoppelten Hintergrundprozess (laeuft nach Sitzungsende weiter?)",
     re.compile(r"(\bnohup\b|\bdisown\b|\bsetsid\b|start_new_session\s*=\s*True|detached\s*:\s*true)", I), True),
    ("MAL-ANTIFORENSIC", "HIGH", "Spuren verwischen (Shell-Verlauf, Ereignisprotokolle, Selbstloeschung, Zeitstempel)",
     re.compile(r"(history\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|>\s*~?/?\.?(bash|zsh)_history|rm\s[^\n]{0,200}\.(bash|zsh)_history|wevtutil(\.exe)?\s+(cl|clear-log)|Clear-EventLog|Remove-EventLog|auditpol\s+/clear|journalctl\s+--(vacuum|rotate)|shred\s+-[a-z]*u|os\.(remove|unlink)\(\s*(__file__|sys\.argv\[0\])|unlink(Sync)?\(\s*__filename\s*\)|rm\s+(-f\s+)?[\"']?\$0[\"']?(\s|$)|Remove-Item[^\n]{0,200}\$MyInvocation|touch\s+-[a-z]*r\s|Set-ItemProperty[^\n]{0,200}(LastWriteTime|CreationTime))", I), False),
    # Schwellen je Einheit: Python time.sleep und Shell sleep zaehlen
    # Sekunden (ab 100 s auffaellig), JS sleep()/setTimeout Millisekunden
    # (erst ab 1000 s bzw. ~17 min, sonst trifft man jeden Test-Timeout).
    ("MAL-SANDBOX-CHECK", "MEDIUM", "Erkennt Analyse-/Testumgebung oder zoegert die Ausfuehrung hinaus (Zeitbombe?)",
     re.compile(r"(IsDebuggerPresent|CheckRemoteDebuggerPresent|sys\.gettrace\(\)|\bVBOX\w*|VirtualBox|SbieDll|sandboxie|wine_get_unix_file_name|/proc/1/cgroup|(?<![.\w])sleep\(\s*\d{6,}\s*\)|(time|asyncio)\.sleep\(\s*\d{3,}\s*\)|(^|[;&|]\s*)sleep\s+\d{3,}\b|setTimeout\([^\n]{0,200},\s*\d{7,}\s*\)|Start-Sleep\s+(-s(econds)?\s+)?\d{3,}|(datetime\.now|datetime\.today|date\.today|new Date)\(\)[^\n]{0,40}[<>]=?\s*(datetime|date|new Date)?\(?\s*20\d\d)", I), True),

    # --- Rechteausweitung
    ("MAL-PRIVESC", "HIGH", "Rechteausweitung (setuid, sudoers, Prozess-Namespace des Hosts)",
     re.compile(r"(chmod\s+[ugoa]*\+s\b|chmod\s+[2467][0-7]{3}\s|/etc/sudoers|\bNOPASSWD\b|os\.setuid\(\s*0\s*\)|nsenter\s+[^\n]{0,200}-t\s*1\b|\bpkexec\b)", I), False),
    ("CODE-CONTAINER-ESC", "MEDIUM", "Zugriff auf Docker-Socket oder privilegierten Container (entspricht Root auf dem Host)",
     re.compile(r"(/var/run/docker\.sock|--privileged\b|privileged\s*:\s*true|--pid[= ]host|--cap-add[= ](SYS_ADMIN|ALL))", I), False),
    ("MAL-SHELLCODE", "HIGH", "Speicher ausfuehrbar machen oder Code in fremde Prozesse einschleusen",
     re.compile(r"(VirtualAlloc(Ex)?\s*\(|VirtualProtect\s*\(|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|RtlMoveMemory|QueueUserAPC|PAGE_EXECUTE_READWRITE|mprotect\([^\n]{0,200}PROT_EXEC|mmap\([^\n]{0,200}PROT_EXEC|ptrace\(\s*PTRACE_(ATTACH|POKETEXT)|\bLD_PRELOAD=|DYLD_INSERT_LIBRARIES)", I), False),
    ("CODE-NATIVE", "MEDIUM", "Ruft native Bibliotheken direkt auf (ctypes/FFI): Verhalten im Quelltext nicht sichtbar",
     re.compile(r"(\bctypes\.(windll|cdll|CDLL|WinDLL|oledll|pythonapi)|\bfrom\s+ctypes\s+import|\bimport\s+ctypes\b|\bcffi\b|ffi-napi|node-ffi|process\.dlopen|Add-Type\s[^\n]{0,200}DllImport|\[DllImport)", I), True),

    # --- Persistenz und Ausbreitung
    ("MAL-PERSIST", "HIGH", "Weitere Persistenz-Orte (Autostart, Dienste, SSH-Schluessel, geplante Aufgaben)",
     re.compile(r"(\.config/autostart|Library/Launch(Agents|Daemons)|/etc/systemd/system/|\.config/systemd/user|/etc/rc\.local|/etc/init\.d/|/etc/cron\.|/var/spool/cron|>>?\s*\S*authorized_keys|authorized_keys[\"']?\s*,\s*[\"']a|Start Menu[/\\]+Programs[/\\]+Startup|CurrentVersion[/\\]+Run(Once)?\b|(New|Register)-ScheduledTask|Register-WmiEvent|__EventFilter|\bPROMPT_COMMAND=)", I), False),
    ("PERSIST-DEV", "MEDIUM", "Git-Hooks setzen (Code laeuft danach bei jedem Commit/Checkout)",
     re.compile(r"(core\.hooksPath(?![= ]+/dev/null)|\.git/hooks/)", I), False),
    # MEDIUM statt HIGH: Installer legitimer Skills (z. B. "kopiere nach
    # .claude/skills") fassen dieselben Pfade an. Ob gelesen oder geschrieben
    # wird und was, entscheidet erst das Lesen des Skripts.
    ("MAL-SKILL-TAMPER", "MEDIUM", "Skript greift auf andere Skills/Plugins oder die Konfiguration von KI-Assistenten zu (schreibt es dort?)",
     re.compile(r"(/mnt/skills\b|\.claude/(skills|plugins|settings(\.local)?\.json|hooks|agents|commands)\b|\.claude\.json\b|claude_desktop_config\.json|\.cursor/mcp\.json|\.vscode/(settings|mcp)\.json|\.codex/|\.gemini/|AppData[/\\]+Roaming[/\\]+Claude)", I), True),
    ("MAL-PUBLISH", "MEDIUM", "Veroeffentlicht Pakete oder pusht in Repos (Wurm-/Supply-Chain-Muster)",
     re.compile(r"(\bnpm\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bgem\s+push\b|\bgit\s+push\b|\bgh\s+(repo\s+create|release\s+create|gist\s+create)\b|\bgit\s+remote\s+(add|set-url)\b)", I), True),

    # --- Abflusskanaele neben dem ueblichen HTTP-Request
    ("NET-ALT-CHANNEL", "MEDIUM", "Abflusskanal neben HTTP (Mail, FTP, SSH/SCP, DNS-Anfragen mit Daten, Messenger-Webhook)",
     re.compile(r"(\bsmtplib\b|\bnodemailer\b|Send-MailMessage|\bsendmail\b|\bftplib\b|ftp://|\bparamiko\b|\bscp\s+\S|\bsftp\s|\brsync\s[^\n]{0,200}?[^\s@]{1,64}@[^\s:]{1,255}:|(gethostbyname|getaddrinfo|dns\.resolver\.(query|resolve)|Resolve-DnsName|nslookup|\bdig)\b[^\n]{0,200}(\{|\+\s*\w|%s|\.format\(|\$\{?\w)|socket\.SOCK_RAW|hooks\.slack\.com|slack\.com/api/chat\.postMessage|\.webhook\.office\.com|outlook\.office\.com/webhook)", I), True),
    ("NET-DYNAMIC-HOST", "MEDIUM", "Netzwerkziel wird zur Laufzeit dekodiert (versteckt das Ziel vor dem Domain-Inventar)",
     re.compile(r"((requests\.\w+|urlopen|httpx\.\w+|fetch|axios\.\w+|https?\.request|Invoke-WebRequest|Invoke-RestMethod)\s*\(\s*((base64\.)?b64decode|atob|bytes\.fromhex|(''|\"\")\.join|chr\(|String\.fromCharCode))", I), True),
    # Zusammengesetzte URLs ('http://' + host) sind in normalem Code
    # alltaeglich; LOW, damit man weiss, dass das Inventar hier lueckenhaft ist.
    ("NET-CONCAT-HOST", "LOW", "Netzwerkziel wird zusammengesetzt: Ziel fehlt im Domain-Inventar",
     re.compile(r"(https?://[\"']\s*\+|https?://\{[a-z_]+\}\.)", I), True),
]

# ---------------------------------------------------------------------------
# Faehigkeiten je Skript und gefaehrliche Kombinationen
# ---------------------------------------------------------------------------
# Warum Kombinationen? Einzelne Faehigkeiten sind meist harmlos: ein
# API-Wrapper braucht Netzwerk, ein Konverter startet pandoc. Gefaehrlich
# wird es, wenn ein Skript eine QUELLE fuer Sensibles (Schluessel, Home,
# Bildschirm) und eine SENKE nach aussen (Netzwerk) vereint. Das ersetzt
# nicht das Verfolgen des Datenflusses beim Lesen, sagt aber, wo man
# zuerst hinschauen muss. Erkennung per Regex statt AST, damit es fuer
# alle Sprachen gleich funktioniert und nichts geparst/ausgefuehrt wird.
CAPABILITIES = [
    ("NET", "Netzwerk", re.compile(
        r"(requests\.(get|post|put|patch|delete|request|Session)|urllib\.request|urlopen|http\.client|\bsocket\.(socket|create_connection)|\baiohttp\b|\bhttpx\.|\bfetch\s*\(|XMLHttpRequest|\baxios\b|new\s+WebSocket|websockets?\.connect|\bsmtplib\b|\bftplib\b|\bparamiko\b|\bnodemailer\b|\bhttps?\.(get|request)\s*\(|\bnet\.(connect|createConnection)|Net\.WebClient|Invoke-(WebRequest|RestMethod)|(^|[\s;&|(`$])(iwr|irm|curl|wget|nc|ncat|scp|sftp)\s|DownloadString|gethostbyname|getaddrinfo|dns\.resolver|\bnslookup\b)", I | re.M)),
    ("SECRETS", "Geheimnisse/Zugangsdaten", re.compile(
        r"(~/\.ssh|\.ssh/|\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials|\.netrc\b|\.git-credentials|\.config/gcloud|\.kube/config|\.docker/config\.json|\.azure/|gh/hosts\.yml|\.claude/\.credentials|\.npmrc|\.pypirc|\.vault-token|/proc/(self|\d+)/environ|_history\b|\bkeychain\b|find-(generic|internet)-password|CryptUnprotectData|Login Data|Local State|key[34]\.db|logins\.json|cookies\.sqlite|Local Storage[/\\]+leveldb|wallet\.dat|169\.254\.169\.254|metadata\.google\.internal|os\.environ\.(items|keys|values)\(\)|json\.dumps\(\s*(dict\()?\s*os\.environ|JSON\.stringify\(\s*process\.env\b|Object\.(keys|entries|values)\(\s*process\.env\s*\)|GetEnvironmentVariables\(\)|\bprintenv\b)", I)),
    ("ENV", "liest Umgebungsvariablen", re.compile(
        r"(os\.environ|os\.getenv|process\.env|\$env:|getenv\(|ENV\[)", I)),
    ("HOME", "Home-Verzeichnis", re.compile(
        r"(expanduser\(|Path\.home\(\)|os\.homedir\(\)|\$HOME\b|~/|%USERPROFILE%|%APPDATA%|\$env:(USERPROFILE|APPDATA))", I)),
    ("FS_WALK", "durchsucht Verzeichnisse", re.compile(
        r"(os\.walk\(|\.rglob\(|glob\.i?glob\([^\n]{0,200}recursive\s*=\s*True|os\.scandir\(|readdirSync\([^\n]{0,200}recursive|walkdir|Get-ChildItem[^\n]{0,200}-Recurse|\bfind\s+(/|~|\$HOME)\S*\s)", I)),
    ("CRYPTO", "verschluesselt", re.compile(
        r"(\bFernet\b|Crypto\.Cipher|Cryptodome|cryptography\.hazmat|\bAES\.new\b|createCipheriv|crypto\.subtle\.encrypt|\bopenssl\s+enc\b|\bChaCha20|nacl\.secret|\bgpg\s+(-c|--symmetric|--encrypt))", I)),
    ("DELETE", "loescht Dateien", re.compile(
        r"(os\.(remove|unlink)\(|shutil\.rmtree|\.unlink\(|fs\.(unlink|rm|rmdir)(Sync)?\(|\brm\s+-|Remove-Item|\bshred\b|\bdel\s+/)", I)),
    ("EXEC", "startet Prozesse/dynamischen Code", re.compile(
        r"(subprocess\.|os\.(system|popen|exec\w*|spawn\w*)\(|child_process|execSync|execFile|\bspawn\s*\(|Start-Process|Invoke-Expression|\biex\b|(?<![.\w])(exec|eval)\s*\(|new\s+Function\s*\(|pty\.spawn|Runtime\.getRuntime)", I)),
    ("DECODE", "dekodiert zur Laufzeit", re.compile(
        r"(b64decode|b32decode|a85decode|\batob\s*\(|bytes\.fromhex|unhexlify|codecs\.decode|zlib\.decompress|gzip\.decompress|lzma\.decompress|marshal\.loads|FromBase64String|Buffer\.from\([^)]{0,200}[\"'](base64|hex)[\"']|base64\s+(-d|--decode))", I)),
    ("SYSINFO", "sammelt Systeminfos", re.compile(
        r"(platform\.(node|uname)\(|socket\.gethostname|getpass\.getuser|os\.getlogin|os\.uname\(|os\.(hostname|userInfo|networkInterfaces)\(|(^\s*|[;&|`]\s*|\$\(\s*)(whoami|hostname|systeminfo|ipconfig|ifconfig)\b(?!\s*[=.:(\[,)])|(system|popen|run|call|check_output|Popen|execSync|exec)\(\s*\[?\s*[\"'](whoami|hostname|systeminfo|ipconfig|ifconfig)\b|uname\s+-a|\$env:(COMPUTERNAME|USERNAME))", I | re.M)),
    ("CAPTURE", "Bildschirm/Tastatur/Zwischenablage/Kamera", re.compile(
        r"(pynput|GetAsyncKeyState|SetWindowsHookEx|CGEventTapCreate|ImageGrab\.grab|pyautogui\.screenshot|\bmss\(\)|\bscreencapture\b|desktopCapturer|getDisplayMedia|pyperclip\.paste|\bpbpaste\b|Get-Clipboard|win32clipboard|cv2\.VideoCapture|getUserMedia|\bpyaudio\b)", I)),
]

NET_RX = dict((cid, rx) for cid, _, rx in CAPABILITIES)["NET"]

def lower_pattern(pattern):
    """Schreibt alle Literale eines Regex klein, laesst Escapes wie \\S,
    \\W, \\B oder \\x7f aber unveraendert (deren Grossbuchstabe hat eine
    eigene Bedeutung). Grund: re.IGNORECASE macht Pythons Regex-Engine
    etwa viermal langsamer. Kleingeschriebenes Muster auf
    kleingeschriebenem Text findet dasselbe, nur schneller."""
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
    """Vorfilter-Variante einer Regel: kleingeschrieben, ohne IGNORECASE,
    mit MULTILINE fuer die Suche ueber die ganze Datei. Liefert eine
    Obermenge der Zeilentreffer: ^/$ greifen an jeder Zeile, \\s kann
    hoechstens zusaetzlich ueber Zeilenenden reichen, und bei Regeln ohne
    IGNORECASE (z. B. MAL-STEALER-BROWSER) ist die kleingeschriebene
    Variante nur grosszuegiger. Es geht also kein Treffer verloren."""
    return re.compile(lower_pattern(rx.pattern), (rx.flags | re.M) & ~re.I)


# Vorfilter aller Regeln und Faehigkeiten, einmal beim Start kompiliert.
RULES_PREFILTER = {rid: prefilter_rx(rx) for rid, _, _, rx, _ in RULES}
assert len(RULES_PREFILTER) == len(RULES), "Regel-IDs muessen eindeutig sein"
CAPS_FAST = [(cid, prefilter_rx(rx)) for cid, _, rx in CAPABILITIES]

# (benoetigte Faehigkeiten, Stufe, Regel-ID, Beschreibung)
# Reihenfolge: spezifisch vor allgemein. Kombinationen, die in normalem
# Werkzeugcode staendig vorkommen (Netz + Prozessstart), sind nur LOW,
# damit die echten Muster nicht im Rauschen untergehen; sie stehen aber im
# Skript-Inventar und werden beim vollstaendigen Lesen geprueft.
COMBOS = [
    ({"SECRETS", "NET"}, "HIGH", "COMBO-EXFIL",
     "Liest Geheimnisse/Zugangsdaten UND hat Netzwerkzugriff: Datenfluss Quelle -> Senke verfolgen"),
    ({"CAPTURE", "NET"}, "HIGH", "COMBO-SPY",
     "Erfasst Bildschirm/Tastatur/Zwischenablage UND hat Netzwerkzugriff"),
    ({"FS_WALK", "CRYPTO", "DELETE"}, "HIGH", "COMBO-RANSOM",
     "Durchsucht Verzeichnisse, verschluesselt UND loescht: Ransomware-Muster"),
    ({"FS_WALK", "HOME", "NET"}, "MEDIUM", "COMBO-COLLECT",
     "Durchsucht das Home-Verzeichnis UND hat Netzwerkzugriff: was wird eingesammelt?"),
    ({"SYSINFO", "NET"}, "MEDIUM", "COMBO-BEACON",
     "Sammelt Systeminfos UND hat Netzwerkzugriff (Beacon/Fingerprinting?)"),
    ({"DECODE", "EXEC"}, "LOW", "COMBO-DECODE-EXEC",
     "Dekodiert zur Laufzeit UND startet Prozesse/Code: pruefen, ob Dekodiertes ausgefuehrt wird"),
    ({"NET", "EXEC"}, "LOW", "COMBO-FETCH-EXEC",
     "Netzwerk UND Prozessstart: pruefen, ob Heruntergeladenes ausgefuehrt wird"),
    ({"ENV", "NET"}, "LOW", "COMBO-ENV-NET",
     "Liest Umgebungsvariablen UND hat Netzwerk: nur der eigene Key an den eigenen Anbieter?"),
]

# Erlaubte Laenge einer Codezeile, bevor sie als minifiziert/verschleiert
# gilt. Normale, gut lesbare Skripte bleiben weit darunter.
LONG_LINE = 3000
HEX_BLOB_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{200,}(?![0-9A-Fa-f])")
IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?![\d.])")

# HTML-Kommentare werden in gerendertem Markdown nicht angezeigt, vom Modell
# aber gelesen. Deshalb separat behandelt: wir melden sie immer (LOW) und
# heben sie an (MEDIUM), wenn darin Instruktionsvokabular steht.
def iter_html_comments(text):
    """Liefert (start, body) fuer jeden HTML-Kommentar. Mit str.find statt
    Regex, weil <!--(.*?)--> bei vielen ungeschlossenen Kommentaren
    quadratisch wird (ein Angreifer kann den Scanner so minutenlang
    aufhalten). Ein ungeschlossener Kommentar wird als eigener Fund
    zurueckgegeben: er versteckt im Rendering den ganzen Rest der Datei."""
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
# Hilfsfunktionen
# ---------------------------------------------------------------------------
def visible_snippet(text, limit=140):
    """Kurzer Ausschnitt fuer den Report. Unsichtbare Zeichen werden als
    <U+XXXX> ausgeschrieben, damit man im Report sieht, was dort steht."""
    out = []
    for ch in text.strip():
        cp = ord(ch)
        if ch in "\r\n":
            # Zeilenumbrueche (z. B. in HTML-Kommentaren) nur als Leerzeichen
            # zeigen, damit der Report einzeilig und lesbar bleibt.
            out.append(" ")
        elif (cp < 32 and ch != "\t") or cp == 0xFEFF or cp >= 0xE0000 or any(
                lo <= cp <= hi for lo, hi, _ in INVISIBLE_RANGES) or cp == 0x200D:
            # Nur wirklich unsichtbare Zeichen ausschreiben; Gedankenstriche,
            # Anfuehrungszeichen usw. bleiben normal lesbar.
            out.append("<U+%04X>" % cp)
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def try_b64(blob):
    """Versucht einen Base64-Block zu dekodieren. Gibt den Klartext zurueck,
    wenn er ueberwiegend druckbar ist (dann war es versteckter Text und
    keine Binaerdatei wie ein eingebettetes Bild)."""
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
    """Ordnet dekodierte Binaerdaten anhand ihrer ersten Bytes ein.
    Rueckgabe: ("EXEC", Bezeichnung) fuer Programme, ("ARCHIVE", ...) fuer
    gepackte Archive,
    ("BENIGN", None) fuer Bilder/Schriften/PDF, None wenn unbekannt.
    Hintergrund: Ein Dropper versteckt sein eigentliches Programm gern als
    Base64- oder Hex-String im Skript und schreibt es zur Laufzeit auf
    die Platte. try_b64() allein wuerde das uebersehen, weil das Ergebnis
    kein Text ist."""
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
    """Zeilennummer des ersten Vorkommens (fuer Funde aus geparstem JSON,
    das selbst keine Zeilennummern kennt). 0, wenn nicht gefunden."""
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 0


# ---------------------------------------------------------------------------
# Manifeste: Code, der beim Installieren oder Starten automatisch laeuft
# ---------------------------------------------------------------------------
# Diese Dateien sind keine Skripte, sorgen aber dafuer, dass Code ohne
# weiteres Zutun ausgefuehrt oder aus dem Netz nachgeladen wird. Genau dort
# setzen die meisten realen Supply-Chain-Angriffe an (npm postinstall,
# Abhaengigkeit aus fremdem Index, MCP-Server mit @latest).
NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepack",
                 "postpack", "preuninstall", "uninstall", "postuninstall",
                 "prepublish")
RISKY_CMD_RE = re.compile(r"(curl|wget|https?://|node\s+-e|python3?\s+-c|eval|base64|\|\s*(ba)?sh|powershell|\biex\b)", re.I)
LAUNCHERS = {"npx", "uvx", "bunx", "pnpx", "pipx", "dlx", "docker", "podman", "deno"}


def json_or_none(text, rel, skill, findings):
    try:
        return json.loads(text)
    except ValueError:
        findings.append((skill, "LOW", "MANIFEST-PARSE", "JSON nicht lesbar - manuell pruefen", rel, 0, ""))
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
                             "npm-Lifecycle-Skript '%s' laeuft bei npm install automatisch" % hook,
                             rel, line_of(text, '"%s"' % hook), visible_snippet(cmd)))
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = pkg.get(section)
        if not isinstance(deps, dict):
            continue
        for name, ver in deps.items():
            if not isinstance(ver, str):
                continue
            v = ver.strip()
            # Git, URL, lokale Datei oder GitHub-Kurzform "user/repo": umgeht
            # die Registry samt deren Malware-Pruefung und Versionsbindung.
            if re.match(r"(git|github:|gitlab:|bitbucket:|https?:|file:|link:)", v) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", v):
                findings.append((skill, "MEDIUM", "PKG-DEP-SOURCE", "Abhaengigkeit '%s' nicht aus der npm-Registry: %s" % (name, v),
                                 rel, line_of(text, '"%s"' % name), ""))
            elif v in ("*", "latest", "") or v.startswith((">", "x")):
                findings.append((skill, "LOW", "PKG-DEP-UNPINNED", "Abhaengigkeit '%s' ohne Versionsbindung (%s)" % (name, v or "leer"),
                                 rel, line_of(text, '"%s"' % name), ""))


def check_requirements(text, rel, skill, findings):
    unpinned = []
    for ln, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"(-i\s|--index-url|--extra-index-url|--trusted-host|-f\s|--find-links)", line):
            # Fremder oder zusaetzlicher Index: klassischer Weg fuer
            # "Dependency Confusion" (gleichnamiges Paket mit hoeherer Version).
            findings.append((skill, "MEDIUM", "PIP-INDEX", "Zusaetzliche/fremde Paketquelle", rel, ln, visible_snippet(line)))
        elif re.search(r"(git\+|https?://|file:|\s@\s)", line):
            findings.append((skill, "MEDIUM", "PIP-DEP-SOURCE", "Paket aus Git/URL statt PyPI", rel, ln, visible_snippet(line)))
        elif line.startswith("-"):
            continue                      # -r, -c, -e . usw.
        elif "==" not in line and "@" not in line:
            unpinned.append(re.split(r"[<>=!~;\[\s]", line)[0])
    if unpinned:
        findings.append((skill, "LOW", "PIP-DEP-UNPINNED", "%d Pakete ohne exakte Version: %s" % (len(unpinned), ", ".join(unpinned[:8])), rel, 0, ""))


def check_python_build(text, rel, skill, findings, name):
    # setup.py ist selbst Code und laeuft bei "pip install" vollstaendig.
    # Ein eigener install/develop/egg_info-Schritt ist dort der typische
    # Ort fuer Schadcode, der nur bei der Installation zuschlaegt.
    if name == "setup.py":
        for ln, line in enumerate(text.splitlines(), 1):
            if re.search(r"(cmdclass|class\s+\w+\(\s*(install|develop|egg_info|build_py|sdist)\b)", line):
                findings.append((skill, "MEDIUM", "SETUP-HOOK", "setup.py ersetzt einen Install-Schritt (laeuft bei pip install)", rel, ln, visible_snippet(line)))
    else:
        for ln, line in enumerate(text.splitlines(), 1):
            if re.search(r"(git\+|index-url|\[\[tool\.(uv|pdm|poetry)\.source\]\]|\[tool\.uv\.sources\]|https?://\S+\.(whl|tar\.gz|zip)|cmdclass)", line, re.I):
                findings.append((skill, "MEDIUM", "PY-DEP-SOURCE", "Abhaengigkeit/Build aus fremder Quelle oder eigener Build-Schritt", rel, ln, visible_snippet(line)))


# Optionen von npx/uvx/docker, deren naechstes Argument ein Wert ist.
# "--python 3.12" darf nicht als Paket "3.12" gelesen werden. Bei
# -p/--package/--from IST der Wert das Paket, das geladen wird.
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
    """Ist das Paket bzw. Image eines Launchers (npx, uvx, docker ...)
    auf eine feste Version gebunden? Ungepinnt laedt jeder Start den
    aktuell veroeffentlichten Code, also ungeprueft."""
    base = os.path.basename(cmd)
    pkg = launcher_package(args)
    if not pkg:
        return True, ""
    if base in ("docker", "podman"):
        return ("@sha256:" in pkg or re.search(r":[\w.-]+$", pkg.split("/")[-1]) is not None) and not pkg.endswith(":latest"), pkg
    if pkg.endswith("@latest"):
        return False, pkg
    # npm: name@1.2.3 bzw. @scope/name@1.2.3; Python: name==1.2.3
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
        findings.append((skill, "INFO", "MCP-SERVER", "MCP-Server '%s': %s" % (name, visible_snippet(desc, 160)), rel, ln, ""))
        scripts_inv[(skill, "%s#%s" % (rel, name))] = {"caps": ["MCP-Server"], "hosts": sorted({m.group(1).lower() for m in URL_RE.finditer(desc)})}
        if cmd and os.path.basename(cmd) in LAUNCHERS:
            ok, pkg = mcp_pinned(cmd, args)
            if not ok:
                findings.append((skill, "MEDIUM", "MCP-UNPINNED",
                                 "MCP-Server '%s' laedt '%s' bei jedem Start ohne feste Version" % (name, pkg), rel, ln, ""))
        if cmd and os.path.basename(cmd) in ("bash", "sh", "zsh", "powershell", "pwsh", "cmd", "cmd.exe"):
            findings.append((skill, "MEDIUM", "MCP-SHELL", "MCP-Server '%s' startet eine Shell: Befehl vollstaendig lesen" % name, rel, ln, visible_snippet(desc)))


def check_hooks(data, text, rel, skill, findings):
    """Hooks laufen bei Ereignissen (Sitzungsstart, vor/nach Werkzeugaufruf)
    automatisch, ohne dass Claude oder der Nutzer sie bewusst startet.
    Jeder Hook-Befehl wird deshalb einzeln gemeldet und muss gelesen werden.
    Prompt-Hooks sind ebenso relevant: ihr Text landet direkt im Kontext."""
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return

    def walk(node, event):
        if isinstance(node, dict):
            for key in ("command", "prompt"):
                val = node.get(key)
                if isinstance(val, str):
                    rid = "HOOK-COMMAND" if key == "command" else "HOOK-PROMPT"
                    findings.append((skill, "MEDIUM", rid, "Hook '%s' laeuft automatisch" % event, rel,
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
        # plugin.json darf hooks/mcpServers auch inline oder als Pfad
        # angeben. Pfade auf ungewoehnliche Orte sind ein Versteck.
        if name == "plugin.json" and isinstance(data, dict):
            if isinstance(data.get("mcpServers"), dict):
                check_mcp_json(json.dumps(data["mcpServers"]), rel, skill, findings, scripts_inv)
            for key in ("hooks", "mcpServers", "commands", "agents"):
                val = data.get(key)
                if isinstance(val, str) and val not in ("./hooks/hooks.json", "./.mcp.json", "./commands", "./agents"):
                    findings.append((skill, "LOW", "PLUGIN-CUSTOM-PATH", "plugin.json verweist '%s' auf %s - dort mitpruefen" % (key, val), rel, line_of(text, '"%s"' % key), ""))


def parse_frontmatter(text):
    """Minimaler YAML-Frontmatter-Parser (nur Top-Level-Schluessel).
    Bewusst kein PyYAML: kein Fremdpaket, und yaml.load waere auf fremden
    Daten selbst ein Risiko."""
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
    """Entpackt .zip/.skill sicher. Prueft Zip-Slip (../, absolute Pfade),
    Symlinks im Archiv und Zip-Bomben, bevor irgendetwas geschrieben wird."""
    with zipfile.ZipFile(archive) as zf:
        members = zf.infolist()
        if len(members) > ZIP_MAX_MEMBERS:
            raise ValueError("Archiv hat zu viele Eintraege (%d)" % len(members))
        total = sum(m.file_size for m in members)
        if total > ZIP_MAX_TOTAL:
            raise ValueError("Archiv entpackt zu gross (%d Bytes) - moegliche Zip-Bombe" % total)
        for m in members:
            name = m.filename
            mode = (m.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                findings.append(("ARCHIVE", "HIGH", "ZIP-SYMLINK", "Symlink im Archiv", name, 0, name))
                continue
            p = Path(name)
            if p.is_absolute() or ".." in p.parts:
                findings.append(("ARCHIVE", "HIGH", "ZIP-SLIP", "Pfad verlaesst Zielordner", name, 0, name))
                continue
            zf.extract(m, dest)


def skill_root_for(path, roots):
    """Ordnet eine Datei dem naechstgelegenen Skill-Ordner (mit SKILL.md) zu."""
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
# Kern: eine Datei scannen
# ---------------------------------------------------------------------------
def scan_file(fpath, rel, skill, findings, domains, scripts_inv):
    ext = fpath.suffix.lower()

    # Symlinks koennen auf ~/.ssh o. ae. zeigen und beim Paketieren echte
    # Geheimnisse einschleusen. Nie folgen, immer melden.
    if fpath.is_symlink():
        findings.append((skill, "HIGH", "FS-SYMLINK", "Symlink -> %s" % os.readlink(fpath), rel, 0, ""))
        return

    st = fpath.stat()
    if st.st_mode & stat.S_IXUSR and ext not in CODE_EXT:
        findings.append((skill, "LOW", "FS-EXEC", "Ausfuehrbar-Bit auf Nicht-Skript", rel, 0, ""))

    if ext in DANGEROUS_BINARY_EXT:
        findings.append((skill, "HIGH", "FS-BINARY", "Ausfuehrbare Binaerdatei im Skill", rel, 0, ""))
        return
    if ext in NESTED_ARCHIVE_EXT:
        findings.append((skill, "MEDIUM", "FS-NESTED-ARCHIVE",
                         "Verschachteltes Archiv: Inhalt NICHT mitgeprueft, separat entpacken bzw. Archiv direkt an den Scanner uebergeben",
                         rel, 0, ""))
        return

    data = fpath.read_bytes()[:MAX_TEXT_BYTES]
    if ext in BENIGN_BINARY_EXT:
        # Endung allein reicht nicht: eine "logo.png", die in Wahrheit ein
        # ELF- oder PE-Programm ist, ist ein klassischer Tarntrick.
        kind = binary_kind(data[:16])
        if kind and kind[0] in ("EXEC", "ARCHIVE"):
            findings.append((skill, "HIGH" if kind[0] == "EXEC" else "MEDIUM", "FS-DISGUISED-BIN",
                             "Datei mit Endung '%s' ist in Wahrheit: %s" % (ext, kind[1]), rel, 0, ""))
        return

    if b"\x00" in data[:8192]:
        # Nullbytes = Binaerdatei mit unerwarteter Endung (Tarnung als .md?)
        kind = binary_kind(data[:16])
        if kind and kind[0] == "EXEC":
            findings.append((skill, "HIGH", "FS-DISGUISED-BIN", "Datei mit Endung '%s' ist in Wahrheit: %s" % (ext or "(keine)", kind[1]), rel, 0, ""))
        else:
            findings.append((skill, "MEDIUM", "FS-UNKNOWN-BIN", "Binaerdatei mit Text-Endung '%s'" % ext, rel, 0, ""))
        return
    text = data.decode("utf-8", "replace")

    # Code erkennt man nicht nur an der Endung: ein "helper" ohne Endung
    # mit "#!/bin/bash" in der ersten Zeile ist genauso ausfuehrbar.
    has_shebang = text.startswith("#!")
    is_code = ext in CODE_EXT or fpath.name in CODE_NAMES or has_shebang
    if has_shebang and ext not in CODE_EXT and fpath.name not in CODE_NAMES:
        if ext in ("", ".bin"):
            findings.append((skill, "LOW", "FS-SHEBANG", "Skript ohne Endung (Shebang: %s)" % visible_snippet(text.splitlines()[0], 60), rel, 1, ""))
        else:
            findings.append((skill, "MEDIUM", "FS-SHEBANG-DISGUISE", "Skript als '%s' getarnt (Shebang: %s)" % (ext, visible_snippet(text.splitlines()[0], 60)), rel, 1, ""))

    if is_code:
        findings.append((skill, "INFO", "CODE-FILE", "Enthaelt ausfuehrbaren Code - vollstaendig lesen", rel, 0, ""))
    if st.st_size > LARGE_TEXT_WARN:
        findings.append((skill, "LOW", "FS-LARGE", "Sehr grosse Textdatei (%d KB) - gutes Versteck" % (st.st_size // 1024), rel, 0, ""))

    check_manifest(fpath, rel, skill, text, findings, scripts_inv)

    # 1) Unsichtbare Zeichen: pro Datei zusammenfassen, sonst flutet ein
    #    einziger Treffer mit tausend Tag-Zeichen den Report.
    inv = find_invisible(text)
    if inv:
        kinds = sorted({k for _, k in inv})
        lines = sorted({ln for ln, _ in inv})[:10]
        hidden = decode_tag_chars(text)
        detail = "%d Zeichen (%s) in Zeilen %s" % (len(inv), ", ".join(kinds), lines)
        if hidden.strip():
            detail += " | dekodierter Tag-Text: " + visible_snippet(hidden, 200)
        findings.append((skill, "HIGH", "UNICODE-INVISIBLE", detail, rel, lines[0], ""))

    lines_list = text.splitlines()

    # 2) Zeilenbasierte Regeln. Vorfilter (siehe prefilter_rx): erst die
    #    ganze, kleingeschriebene Datei durchsuchen und nur bei einem Treffer
    #    Zeile fuer Zeile mit der genauen Regel pruefen. Bei grossen
    #    Datendateien spart das den Grossteil der Laufzeit.
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
            findings.append((skill, "MEDIUM", "HOMOGLYPH", "Gemischte Schriftsysteme in: %s" % ", ".join(mixed[:5]), rel, ln, visible_snippet(line)))
        for m in URL_RE.finditer(line):
            domains[skill].add(m.group(1).lower().rstrip("."))

    # 3) HTML-Kommentare (unsichtbar im Rendering)
    if ext in (".md", ".html", ".htm", ".txt", ""):
        for start, body, unclosed in iter_html_comments(text):
            ln = text.count("\n", 0, start) + 1
            if unclosed:
                findings.append((skill, "MEDIUM", "HTML-COMMENT-OPEN", "Ungeschlossener HTML-Kommentar: Rest der Datei im Rendering unsichtbar", rel, ln, visible_snippet(body)))
                break
            sev = "MEDIUM" if IMPERATIVE_RE.search(body) else "LOW"
            findings.append((skill, sev, "HTML-COMMENT", "HTML-Kommentar (im Rendering unsichtbar)", rel, ln, visible_snippet(body)))

    # 4) Base64-Bloecke: melden, wenn sie zu Text dekodieren (versteckte
    #    Anweisung) oder zu einem Programm/Archiv (versteckter Payload).
    #    Eingebettete Bilder (data:image/...;base64) sind normal.
    for m in B64_RE.finditer(text):
        before = text[max(0, m.start() - 40): m.start()]
        if "base64," in before and ("data:image" in before or "data:font" in before or "data:application/font" in before):
            continue
        ln = text.count("\n", 0, m.start()) + 1
        decoded = try_b64(m.group(0))
        if decoded:
            sev = "HIGH" if re.search(r"(https?://|ignore|instruction|curl|password|token|system)", decoded, I) else "MEDIUM"
            findings.append((skill, sev, "OBF-BASE64", "Base64-Block dekodiert zu Text", rel, ln, visible_snippet(decoded, 160)))
            continue
        kind = binary_kind(decode_b64_bytes(m.group(0)[:64]))
        if kind and kind[0] in ("EXEC", "ARCHIVE"):
            sev = "HIGH" if kind[0] == "EXEC" else "MEDIUM"
            findings.append((skill, sev, "OBF-PAYLOAD", "Base64-Block enthaelt %s (%d Zeichen)" % (kind[1], len(m.group(0))), rel, ln, ""))
        elif kind is None and is_code and len(m.group(0)) >= 400 and ext != ".ipynb":
            findings.append((skill, "MEDIUM", "OBF-BLOB", "Grosser Base64-Block im Code dekodiert zu unbekannten Binaerdaten (gepackter/verschluesselter Payload?)", rel, ln, ""))

    if not is_code:
        return

    # 5) Nur fuer Code: Hex-Payloads, minifizierte Zeilen, Faehigkeiten.
    for m in HEX_BLOB_RE.finditer(text):
        kind = binary_kind(bytes.fromhex(m.group(0)[:64]))
        if kind and kind[0] in ("EXEC", "ARCHIVE"):
            ln = text.count("\n", 0, m.start()) + 1
            findings.append((skill, "HIGH" if kind[0] == "EXEC" else "MEDIUM", "OBF-PAYLOAD", "Hex-Block enthaelt %s (%d Zeichen)" % (kind[1], len(m.group(0))), rel, ln, ""))

    if ext != ".ipynb":
        for ln, line in enumerate(lines_list, 1):
            if len(line) > LONG_LINE:
                findings.append((skill, "LOW", "OBF-LONGLINE", "Sehr lange Codezeile (%d Zeichen): minifiziert oder verschleiert? Quelltext vorhanden?" % len(line), rel, ln, ""))
                break

    caps = [cid for cid, rx in CAPS_FAST if rx.search(low)]
    hosts = set()
    for line in lines_list:
        for m in URL_RE.finditer(line):
            hosts.add(m.group(1).lower().rstrip("."))
        # Nackte IPs nur in Zeilen mit Netzwerkbezug, sonst landen
        # Versionsnummern wie 1.2.3.4 im Inventar.
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
    """Prueft SKILL.md-Kopf: Pflichtfelder und vor allem 'allowed-tools',
    weil ein Skill damit Werkzeugrechte ohne Rueckfrage beanspruchen kann."""
    sk = skill_dir / "SKILL.md"
    if not sk.exists():
        return
    text = sk.read_text("utf-8", "replace")
    fm = parse_frontmatter(text)
    if fm is None:
        findings.append((skill, "MEDIUM", "FM-MISSING", "Kein YAML-Frontmatter in SKILL.md", "SKILL.md", 1, ""))
        return
    if not fm.get("name") or not fm.get("description"):
        findings.append((skill, "MEDIUM", "FM-FIELDS", "name/description fehlt", "SKILL.md", 1, ""))
    if fm.get("name") and fm["name"] != skill_dir.name:
        findings.append((skill, "LOW", "FM-NAME", "name '%s' != Ordner '%s'" % (fm["name"], skill_dir.name), "SKILL.md", 1, ""))
    if len(fm.get("description", "")) > 1024:
        findings.append((skill, "LOW", "FM-DESC-LONG", "description > 1024 Zeichen (Trigger-Hijacking moeglich)", "SKILL.md", 1, ""))
    for key in ("allowed-tools", "allowed_tools", "tools"):
        if key in fm:
            findings.append((skill, "MEDIUM", "FM-ALLOWED-TOOLS", "Beansprucht Werkzeugrechte: %s=%s" % (key, fm[key] or "(Liste)"), "SKILL.md", 1, ""))


# ---------------------------------------------------------------------------
# Hauptablauf
# ---------------------------------------------------------------------------
# Archivformate, die intern ZIP sind und sich sicher entpacken lassen.
ZIP_BASED_EXT = (".zip", ".skill", ".plugin", ".whl", ".vsix", ".xpi", ".egg")


def scan_paths(paths):
    findings = []                 # (skill, severity, rule, beschreibung, datei, zeile, ausschnitt)
    domains = defaultdict(set)
    scripts_inv = {}              # (skill, datei) -> {"caps": [...], "hosts": [...]}
    skills_seen = set()           # damit auch fundlose Skills im Report erscheinen
    file_count = 0
    tmpdirs = []
    targets = []

    for p in paths:
        p = Path(p).resolve()
        if p.is_file() and p.suffix.lower() in ZIP_BASED_EXT and zipfile.is_zipfile(p):
            # Archive in eigenen, leeren Temp-Ordner entpacken, damit fremde
            # Dateien nie neben eigenen Skripten landen.
            td = Path(tempfile.mkdtemp(prefix="skillcheck_"))
            tmpdirs.append(td)
            try:
                safe_extract(p, td, findings)
            except (ValueError, zipfile.BadZipFile, OSError) as e:
                findings.append(("(Archiv)", "HIGH", "ARCHIVE-ERROR", "Archiv nicht sicher entpackbar: %s" % e, p.name, 0, ""))
            targets.append(td)
        else:
            targets.append(p)

    # Je Ziel: (Ordner, Verschachtelungstiefe, Anzeigename des Archivs).
    targets = [(t, 0, "") for t in targets]
    for base, depth, label in targets:
        # Skill-Ordner = jeder Ordner mit SKILL.md. Symlinks nicht folgen.
        roots = sorted({f.parent for f in base.rglob("SKILL.md") if not f.is_symlink() and f.is_file()})
        for f in base.rglob("SKILL.md"):
            if f.is_dir() and not f.is_symlink():
                findings.append((f.parent.name, "HIGH", "FS-FAKE-SKILLMD", "SKILL.md ist ein Verzeichnis, kein Skill: Tarnung oder Scanner-Angriff", str(f.relative_to(base)), 0, ""))
        # Anzeigename je Wurzel. Bei verschachtelten Archiven mit Herkunft
        # ("plugin/vendor/x.skill!/x"), damit klar ist, woher ein Fund stammt.
        prefix = label + "!/" if label else ""
        root_names = {r: prefix + r.name for r in roots}
        for r in roots:
            skills_seen.add(root_names[r])
            try:
                check_frontmatter(r, root_names[r], findings)
            except Exception as e:  # noqa: BLE001
                findings.append((root_names[r], "HIGH", "SCAN-ERROR", "SKILL.md nicht pruefbar (%s: %s)" % (type(e).__name__, e), "SKILL.md", 0, ""))
        # Plugin-Ordner = Ordner mit .claude-plugin/plugin.json. Dateien auf
        # Plugin-Ebene (.mcp.json, hooks/, package.json) gehoeren keinem
        # Skill, sind aber oft die riskantesten; sie werden deshalb dem
        # Plugin zugeordnet statt unter "(ausserhalb Skill)" zu verschwinden.
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
            # Verschachtelte ZIP-basierte Archive (.skill in einem Plugin,
            # .whl in vendor/) sicher entpacken und mitpruefen, statt sie nur
            # als "ungeprueft" zu melden. Maximal zwei Ebenen tief.
            if (not f.is_symlink() and f.suffix.lower() in ZIP_BASED_EXT and depth < 2
                    and zipfile.is_zipfile(f)):
                td = Path(tempfile.mkdtemp(prefix="skillcheck_"))
                tmpdirs.append(td)
                inner_label = (label + "!/" if label else "") + str(f.relative_to(base))
                try:
                    safe_extract(f, td, findings)
                    targets.append((td, depth + 1, inner_label))
                    findings.append(("(Archiv)", "INFO", "ARCHIVE-SCANNED", "Verschachteltes Archiv entpackt und mitgeprueft", inner_label, 0, ""))
                    file_count += 1
                    continue
                except (ValueError, zipfile.BadZipFile, OSError) as e:
                    findings.append(("(Archiv)", "MEDIUM", "FS-NESTED-ARCHIVE", "Archiv nicht pruefbar: %s" % e, inner_label, 0, ""))
                    continue
            root = skill_root_for(f, all_roots)
            if root is None:
                skill = "(ausserhalb Skill)"
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
            except Exception as e:  # noqa: BLE001 - Scanner darf nie fail-open sein
                findings.append((skill, "HIGH", "SCAN-ERROR", "Datei hat den Scanner zum Absturz gebracht (%s: %s) - manuell pruefen" % (type(e).__name__, e), rel, 0, ""))
    return findings, domains, skills_seen, file_count, tmpdirs, scripts_inv


def cleanup(tmpdirs):
    """Entpackte Archive wieder loeschen: fremder Inhalt soll nicht im
    Temp-Ordner liegen bleiben."""
    for td in tmpdirs:
        shutil.rmtree(td, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Statischer Sicherheits-Scanner fuer Agent-Skills")
    ap.add_argument("paths", nargs="+", help="Skill-Ordner, Sammelordner oder .zip/.skill")
    ap.add_argument("--json", help="Funde zusaetzlich als JSON speichern")
    ap.add_argument("--min-severity", default="LOW", choices=SEVERITIES, help="Untergrenze fuer die Textausgabe")
    ap.add_argument("--max-per-rule", type=int, default=8, help="Max. Zeilen pro Regel und Skill in der Textausgabe")
    args = ap.parse_args()

    findings, domains, skills_seen, file_count, tmpdirs, scripts_inv = scan_paths(args.paths)
    cleanup(tmpdirs)

    # Zusammenfassung pro Skill
    by_skill = defaultdict(list)
    for f in findings:
        by_skill[f[0]].append(f)
    all_skills = sorted(skills_seen | set(by_skill) | set(domains))

    worst_overall = "INFO"
    print("# skillcheck Scan-Report")
    print("Gescannte Dateien: %d | Skills: %d | Funde: %d\n" % (file_count, len(all_skills), len(findings)))
    print("## Uebersicht (hoechster Schweregrad je Skill)")
    for s in all_skills:
        sevs = [f[1] for f in by_skill.get(s, [])] or ["INFO"]
        worst = max(sevs, key=sev_rank)
        if sev_rank(worst) > sev_rank(worst_overall):
            worst_overall = worst
        counts = {k: sevs.count(k) for k in SEVERITIES if k in sevs and k != "INFO"}
        print("- %-28s %-6s %s" % (s, worst, " ".join("%s=%d" % kv for kv in counts.items())))

    print("\n## Funde ab %s" % args.min_severity)
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
                    print("  - [%s] %s: ... weitere Treffer gekuerzt (siehe JSON)" % (sev, rid))
                continue
            loc = "%s:%d" % (rel, ln) if ln else rel
            print("  - [%s] %s %s - %s%s" % (sev, rid, loc, desc, ("\n      > " + snip) if snip else ""))

    # Skript-Inventar: Startpunkt fuer Schritt 5 (Skriptanalyse). Pro Datei
    # mit Code die erkannten Faehigkeiten und Netzwerkziele. Ziel ist der
    # Abgleich "Zweck laut SKILL.md" gegen "was der Code kann".
    if scripts_inv:
        labels = {cid: label for cid, label, _ in CAPABILITIES}
        print("\n## Skript-Inventar (Faehigkeiten und Netzwerkziele je Code-Datei)")
        for (s, rel) in sorted(scripts_inv):
            info = scripts_inv[(s, rel)]
            caps = ", ".join(labels.get(c, c) for c in info["caps"]) or "keine erkannt"
            hosts = ", ".join(info["hosts"]) or "-"
            print("- %s/%s\n    Faehigkeiten: %s\n    Ziele: %s" % (s, rel, caps, hosts))

    print("\n## Domain-Inventar (alle URLs je Skill)")
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
