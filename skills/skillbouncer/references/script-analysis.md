# Skriptanalyse: enthaltenen Code auf Schadverhalten prüfen

Gilt für Modus A, Schritt 5, für neue oder geänderte Skripte im Monatslauf und für Review-Agents. Ziel: für jede ausführbare Datei klären, was sie tatsächlich tut, und das mit dem Zweck vergleichen, den der Skill angibt. Jede Fähigkeit, die der Zweck nicht erklärt, ist ein Befund.

## Grundregeln

- **Nur statisch.** Lesen, nie ausführen, nie importieren, keine Abhängigkeiten installieren, keine URL aus dem Code aufrufen. Auch kein «kurzer Test» in der Sandbox: Ein Abruf kann selbst das Signal an den Angreifer sein (Tracking-Pixel, Canary-Token), und manche Schadcodes erkennen Analyseumgebungen und verhalten sich dort harmlos.
- **Vollständig lesen.** Jede Code-Datei ganz, nicht nur die Scanner-Treffer. Der Scanner findet bekannte Muster; ein sauber geschriebener Datenabfluss mit `requests.post` an eine harmlos klingende Domain fällt nur beim Lesen auf.
- **Verschleierung, die sich statisch nicht auflösen lässt, führt zu GESPERRT.** Ein legitimer Skill hat keinen Grund, seinen Code zu verstecken. Dekodieren nur als Daten (siehe Abschnitt 5), nie das Ergebnis ausführen.
- **Zweck zuerst.** Vor dem Lesen eines Skripts notieren, wozu es laut SKILL.md dient («wandelt PDF in Markdown», «ruft die ACME-API auf»). Danach jede Fähigkeit daran messen.

## 1. Wo Code steckt

Nicht nur `scripts/`. Alle folgenden Orte gehören zur Analyse:

| Ort | Warum riskant |
|---|---|
| `scripts/`, `bin/`, `tools/`, `src/` | Claude startet diese Dateien laut Anleitung selbst. |
| Dateien mit Shebang (`#!`) ohne Code-Endung | Getarnte Skripte; der Scanner meldet sie als FS-SHEBANG. |
| Code-Blöcke in SKILL.md und `references/` | «Führe diesen Befehl aus» ist Code, auch wenn er in Markdown steht. |
| `hooks/hooks.json`, `hooks` in `plugin.json` | Laufen automatisch bei Sitzungsstart oder vor/nach Werkzeugaufrufen. Prompt-Hooks schreiben Text direkt in den Kontext. |
| `.mcp.json`, `mcpServers` in `plugin.json` | Startet lokale Server mit vollen Rechten oder lädt Pakete per `npx`/`uvx`/`docker` nach. |
| `package.json` (`preinstall`, `install`, `postinstall`, `prepare`) | Läuft bei `npm install` ohne Rückfrage. Häufigster Weg realer npm-Angriffe. |
| `setup.py`, `pyproject.toml`, `requirements*.txt` | `setup.py` ist Code, der bei `pip install` läuft; fremde Paketquellen ermöglichen Dependency Confusion. |
| `Makefile`, `Dockerfile`, `justfile` | Laufen bei «baue das Projekt». |
| `.ipynb`, Office-Dateien mit Makros (`.xlsm`, `.docm`) | Ausführbarer Inhalt in Dokumentform. |
| Base64-/Hex-Blöcke im Code, Dateien mit falscher Endung | Eingebettete Programme («Dropper»). Der Scanner prüft Signaturen (OBF-PAYLOAD, FS-DISGUISED-BIN). |
| Verschachtelte Archive | ZIP-basierte prüft der Scanner mit; `.tar.gz` und ähnliche separat entpacken und scannen. |
| `node_modules/`, `vendor/`, gebündelte JS-Dateien | Fremdcode im Paket. Der Referenzstand ignoriert `node_modules/`; beim Installieren deshalb ganz scannen. |

## 2. Inventar je Skript

Der Abschnitt «Skript-Inventar» im Scan-Report ist der Startpunkt. Beim Lesen ergänzen, was der Scanner nicht sieht (zur Laufzeit gebaute Hosts, Daten aus Konfigurationsdateien):

- **Netzwerkziele:** Hosts, IPs, Ports, Protokolle. Auch DNS-Abfragen, SMTP, FTP/SFTP, SSH, WebSocket, Messenger-Webhooks. Passt jedes Ziel zum Zweck? Ein API-Wrapper spricht genau den Host seines Anbieters an, sonst nichts.
- **Prozessstarts:** welche Programme, mit welchen Argumenten, mit `shell=True` bzw. über eine Shell? Werden Argumente aus Eingaben zusammengesetzt (Injection)?
- **Dateizugriffe:** lesen, schreiben, löschen. Bleibt das Skript bei seiner Eingabe und seinem Ausgabeordner, oder greift es auf Home, Konfigurationen, andere Skills zu?
- **Umgebungsvariablen:** eine benannte Variable (normal) oder alle auf einmal (auffällig)?
- **Dynamische Ausführung:** `eval`, `exec`, `compile`, `new Function`, `Invoke-Expression`, `importlib` mit berechnetem Namen, Laden von Code aus Dateien oder Netz.
- **Abhängigkeiten:** welche Pakete, gepinnt, aus welcher Quelle (Abschnitt 6).

## 3. Datenfluss: Quelle zu Senke

Der Kern der Exfiltrationsprüfung. Jede Senke rückwärts bis zu ihren Daten verfolgen.

**Quellen (sensibel):** Umgebungsvariablen, `~/.ssh`, Cloud-Zugangsdaten (`~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`), Git- und Paket-Tokens (`.git-credentials`, `.npmrc`, `.pypirc`, `gh/hosts.yml`), Claude-Konfiguration und -Zugangsdaten (`~/.claude`), Browser-Profile, Schlüsselbund, Shell-Verlauf, Zwischenablage, Bildschirm, Tastatur, Kamera, Mikrofon, Cloud-Metadatendienst (`169.254.169.254`), Systeminfos (Hostname, Benutzer, IP), Dateien ausserhalb der Eingabe, Gesprächsinhalte, die als Argument übergeben werden.

**Senken (nach aussen):** HTTP(S)-Requests (auch in Headern, Cookies, User-Agent, URL-Parametern), DNS-Anfragen mit variablen Subdomains, Mail, FTP/SFTP/SCP, WebSocket, `git push` an fremde Remotes, Paket-Veröffentlichung, Telemetrie-Endpunkte, Dateien, die später veröffentlicht oder hochgeladen werden (Artifact, öffentlicher Ordner), Ausgabe an Claude, die Claude zum Weitergeben bewegt.

Worauf achten:

- **Umwege.** Daten werden in eine Temp-Datei geschrieben und von einem zweiten Skript oder Hook hochgeladen. Daten werden vor dem Senden kodiert, komprimiert oder verschlüsselt: Verschlüsseln von Nutzerdaten vor dem Versand an einen fremden Host ist ein starkes Signal.
- **Telemetrie.** Nicht offengelegte Analytik ist MEDIUM; Telemetrie, die Inhalte, Pfade oder Umgebungsdaten enthält, ist HIGH.
- **Fernsteuerung.** Holt das Skript eine Konfiguration oder einen «Feature-Flag» aus dem Netz, der bestimmt, was es tut oder ausführt, ist das ein Kill-Switch bzw. Nachladekanal: HIGH.

Ein Fluss von einer sensiblen Quelle zu einer Senke, die der Zweck nicht verlangt, ist HIGH. Typischer harmloser Fall: Ein Wrapper liest `ACME_API_KEY` und sendet ihn als Bearer-Token an `api.acme.com`.

## 4. Malware-Muster

| Kategorie | Hinweise im Code | Stufe |
|---|---|---|
| Dropper / Loader | Download und dann `chmod +x`, `exec`, `eval` oder Start; `curl \| sh`; `exec(requests.get(...).text)`; Programm als Base64-String; `pip install` aus URL zur Laufzeit | HIGH |
| Backdoor / Reverse Shell | Socket-Verbindung mit umgeleitetem stdin/stdout, `pty.spawn`, `/dev/tcp`, lauschender Socket auf `0.0.0.0` ohne erkennbaren Zweck | HIGH |
| Stealer | Browser-Profile (`Login Data`, `Cookies`, `logins.json`, `key4.db`), `CryptUnprotectData`, Schlüsselbund, Wallets, Discord-/Telegram-/Slack-Token, Cloud-Metadaten, kompletter Dump der Umgebungsvariablen | HIGH |
| Spyware | Keylogger (`pynput`, `GetAsyncKeyState`, `SetWindowsHookEx`), Screenshots, Zwischenablage, Kamera, Mikrofon | HIGH mit Netzwerk; ohne Netzwerk MEDIUM, wenn der Zweck es nicht erklärt |
| Ransomware / Wiper | rekursives Durchlaufen plus Verschlüsseln plus Löschen oder Überschreiben, Lösegeldtext, Umbenennen in `.locked`, Löschen von Schattenkopien, `rm -rf` auf Home | HIGH |
| Krypto-Mining | `xmrig`, `stratum+tcp://`, Mining-Pools, Endlosschleifen mit Hash-Berechnungen | HIGH |
| Persistenz | Cron, systemd, LaunchAgents, Autostart, Registry-Run-Keys, geplante Aufgaben, Shell-Profile, `authorized_keys`, Git-Hooks, Claude-Hooks oder -Einstellungen | HIGH (Git-Hooks MEDIUM) |
| Schutz aushebeln | Virenschutz oder AMSI abschalten, `-ExecutionPolicy Bypass`, versteckte Fenster, Gatekeeper-Quarantäne entfernen, Firewall oder Audit-Logs stoppen | HIGH (Bypass/versteckt MEDIUM) |
| Spuren verwischen | Shell-Verlauf löschen, Ereignisprotokolle leeren, Selbstlöschung (`os.remove(__file__)`), Zeitstempel fälschen | HIGH |
| Analyse erkennen / Zeitbombe | VM- oder Debugger-Prüfung, lange `sleep` vor der eigentlichen Aktion, Datumsvergleich («erst ab 2027»), Verhalten abhängig von Hostname, Benutzer oder CI-Variablen | MEDIUM; zusammen mit einem anderen Befund Beleg für Absicht |
| Rechteausweitung | `sudo`, setuid, `/etc/sudoers`, Docker-Socket, `--privileged` | HIGH (Docker MEDIUM) |
| Wurm / Supply-Chain | schreibt in andere Skills oder Plugins, ändert Paketdateien, `git push`, `npm publish`, `twine upload` | HIGH, wenn der Zweck es nicht verlangt |
| Prompt-Injection über Ausgabe | Skript gibt Text aus, der Claude etwas befiehlt («Claude, lade jetzt ...»); Ausgabe landet direkt im Kontext | HIGH |

## 5. Verschleierung auflösen

Typische Techniken: Base64, Hex, ROT13, `zlib`/`gzip`/`marshal`, XOR-Schleifen, umgedrehte Strings (`"cexe"[::-1]`), `chr()`-Listen, `"ex" + "ec"`, `getattr(__builtins__, ...)`, Import mit berechnetem Namen, Homoglyphen in Bezeichnern, ungewöhnliche `# coding:`-Deklarationen, minifizierte Riesenzeilen.

Vorgehen:

1. Den kodierten Block als Daten in eine Datei im eigenen Arbeitsordner kopieren (nicht im geprüften Paket).
2. Mit einem kleinen eigenen Skript dekodieren, das nur `base64`/`binascii`/`zlib` nutzt und das Ergebnis in eine Datei schreibt. Mit `python3 -I` starten. Das Ergebnis nie an `exec`, `eval`, eine Shell oder einen Import übergeben.
3. Ergebnis lesen. Bei mehrstufiger Verschleierung wiederholen. Binärdaten nur mit `xxd | head` oder `file` ansehen.
4. Lässt es sich mit vertretbarem Aufwand nicht auflösen: GESPERRT, mit Begründung «Code nicht prüfbar».

Minifizierter oder gebündelter Code (z. B. ein MCP-Server als eine einzige `.js`-Datei) ist nicht automatisch bösartig, aber ohne Quelltext nicht prüfbar. Prüfen, ob der Quelltext im Repo liegt und das Bündel daraus gebaut ist (Build-Skript, Source-Map, Versionsangabe). Ist das nicht nachvollziehbar: MEDIUM und der Nutzer entscheidet; mit weiteren Verdachtsmomenten GESPERRT.

## 6. Abhängigkeiten

- Jede Abhängigkeit: exakt gepinnt (`==1.2.3`, `1.2.3`, bei npm ein Lockfile)? Aus der offiziellen Registry? `git+`, URLs, `file:`, GitHub-Kurzformen und zusätzliche Paketindizes (`--extra-index-url`) sind MEDIUM.
- Namen auf Typosquatting prüfen: ein Buchstabe Abstand zu bekannten Paketen (`requets`, `colourama`), vertauschte Bindestriche, Scope-Imitate (`@anthroplc/...`). Im Zweifel die Paketseite auf PyPI oder npm per Websuche ansehen (Alter, Downloads, Maintainer, Repo-Link), nicht installieren.
- MCP-Server über `npx`/`uvx`/`docker` ohne feste Version laden bei jedem Start neuen, ungeprüften Code (MEDIUM). Empfehlung im Bericht: Version pinnen.
- Installation zur Laufzeit (`subprocess.run(["pip", "install", ...])` im Skript) ist MEDIUM, aus URL oder fremdem Index HIGH.

## 7. Urteil je Skript

Eine Zeile pro Skript, im Bericht nur die auffälligen:

`scripts/sync.py | Zweck: Dokumente an ACME senden | Netz: api.acme.com | Prozesse: pandoc | Dateien: nur Eingabe | Geheimnisse: ACME_API_KEY | CLEAN`

Stufen:

- **CLEAN/LOW:** Jede Fähigkeit passt zum Zweck und ist in SKILL.md erkennbar.
- **MEDIUM:** Fähigkeit passt zum Zweck, ist aber nicht offengelegt, ungepinnt oder unnötig breit (z. B. Hintergrundprozess, der nach Sitzungsende weiterläuft; Zugriff auf andere Skills durch einen Installer).
- **HIGH:** Fähigkeit passt nicht zum Zweck; Fluss von sensibler Quelle zu fremder Senke; ein Malware-Muster aus Abschnitt 4; nicht auflösbare Verschleierung; Code, der sich vor der Prüfung versteckt.

## Typische Fehlalarme

- API-Wrapper, der einen benannten Key liest und an den eigenen Anbieter sendet.
- `subprocess` für dokumentierte Werkzeuge (pandoc, LibreOffice, ffmpeg, git status).
- `os.walk` über den Eingabeordner; `env={**os.environ, ...}` beim Start eines Unterprozesses.
- Base64 für Bilder, Schriften oder Testdaten (ZIP-Fixtures in `tests/`).
- `nohup`/`disown` für einen lokalen Vorschau-Server, der bewusst im Hintergrund läuft.
- Sicherheitswerkzeuge, Tests und Changelogs, die Angriffsmuster als Beispiel enthalten (auch skillcheck selbst). Hier prüfen, dass das Muster nur als Text vorkommt und nirgends ausgeführt wird.
