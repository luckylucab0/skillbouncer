# skillbouncer

[English](README.md) | Deutsch

skillbouncer ist ein Claude-Plugin, das fremde Claude-Skills und -Plugins
prüft, bevor sie installiert werden, und die installierten einmal im Monat
auf Änderungen kontrolliert, die über Updates hereingekommen sind. Es besteht
aus einem Skill (dem Prüfablauf, dem Claude folgt) und zwei Python-Skripten,
die nur die Standardbibliothek brauchen: einem statischen Musterscanner und
einem Werkzeug für den Hash-Referenzstand (Baseline).

Die Skill-Texte, die Meldungen der Skripte und die übrige Dokumentation sind
englisch. Claude antwortet trotzdem in der Sprache des Nutzers.

## Was es tut und was nicht

Es tut Folgendes:

- Ein Paket nach bekannten Mustern durchsuchen: Prompt-Injection,
  Datenabfluss, Zugriff auf Zugangsdaten, Schadcode in mitgelieferten
  Skripten, Install-Hooks, MCP-Server-Konfigurationen, Dateien, die von
  selbst starten, getarnte Binärdateien und Markdown, das im Rendering
  unsichtbar ist, vom Modell aber gelesen wird.
- Claude einen festen Ablauf vorgeben: das Paket vollständig lesen,
  Datenflüsse in Skripten verfolgen und ein Urteil schreiben, das jeden
  ernsten Treffer begründet.
- Pro Datei einen SHA-256-Hash des geprüften Stands festhalten und später
  melden, welche Dateien neu, geändert oder verschwunden sind.

Es tut Folgendes nicht:

- Etwas ausführen. Die Analyse ist rein statisch. Der Scanner führt nichts
  von dem aus, was er prüft, importiert nichts daraus und ruft nichts ab. Es
  gibt also keine Verhaltensanalyse, und zur Laufzeit wird nichts beobachtet.
- Allein ein Urteil fällen. Der Scanner ist ein Filter. Er findet
  Kandidaten, die Claude oder ein Mensch im Zusammenhang lesen muss. Ein
  leerer Bericht heisst «keine bekannten Muster», nicht «sicher».
- Installierte Plugins einsperren oder überwachen. Ist ein Plugin
  installiert, bemerkt skillbouncer nur, dass sich seine Dateien geändert
  haben, und das erst beim nächsten Monatslauf.

## Installation

Jedem Release liegt eine Plugin-Datei bei, zum Beispiel
`skillbouncer-v1.2.0.plugin`. Eine `.plugin`-Datei ist ein ZIP-Archiv mit
`.claude-plugin/plugin.json` im Wurzelverzeichnis. Lade sie von der
Release-Seite dieses Repositorys herunter und lade sie in der Claude-App
unter Anpassen > Plugins hoch.

So baust du die Datei aus einem Checkout, im Wurzelverzeichnis des
Repositorys:

```bash
zip -r skillbouncer-v1.2.0.plugin . \
    -x '.git/*' '.github/*' 'tests/*' 'docs/*' 'README.md' 'README.de.md' \
       'CHANGELOG.md' 'CLAUDE.md' '.gitignore' '*__pycache__*' '*.plugin'
```

Die Ausschlüsse halten Tests, Repository-Metadaten und Entwicklerdokumente
aus dem Paket heraus. `__pycache__`-Ordner entstehen beim Ausführen der
Tests und würden vom Scanner als Binärdateien gemeldet, und `*.plugin` hält
frühere Builds fern. Das Ergebnis enthält `.claude-plugin/`, `skills/` und
`LICENSE`.

Richte nach der Installation die monatliche Aufgabe ein (siehe unten), wenn
du Modus B nutzen willst.

## Die zwei Modi

**Modus A: Prüfung vor der Installation.** Claude holt das Paket, ohne es zu
benutzen, erstellt ein Inventar, lässt den Scanner laufen, liest jede
SKILL.md, jede Referenzdatei und jedes Skript vollständig, analysiert die
Skripte auf Schadverhalten und meldet ein Urteil: APPROVED (freigegeben),
APPROVED WITH NOTES (freigegeben mit Hinweisen) oder BLOCKED (gesperrt). Ein
freigegebenes Paket wird aus genau dem geprüften Stand installiert und in
den Referenzstand aufgenommen. Der Ablauf steht in
`skills/skillbouncer/SKILL.md`, die Checkliste für Skripte in
`skills/skillbouncer/references/script-analysis.md`.

**Modus B: monatlicher Abgleich mit dem Hash-Referenzstand.** Eine geplante
Aufgabe prüft zuerst die eigenen Dateien von skillbouncer, erfasst die
aktuellen Hashes von allem, was installiert ist, vergleicht sie mit dem
Referenzstand und prüft nur, was neu oder geändert ist. Unauffällige
Änderungen aktualisieren den Referenzstand. Alles andere wird als PENDING
markiert und wartet auf die Entscheidung des Nutzers. Weicht die
Scanner-Version von der im Referenzstand vermerkten ab, wird jede Einheit
neu gescannt, denn Einheiten, die unter älteren Regeln freigegeben wurden,
haben die neuen Regeln nie gesehen. Der Ablauf steht in
`skills/skillbouncer/references/monthly-run.md`.

## Schweregrade und Exit-Codes

| Stufe | Bedeutung | Beispiele |
|-------|-----------|-----------|
| HIGH | Sperrt die Installation, solange nicht jeder Treffer schriftlich als Fehlalarm begründet ist. | Versteckte Anweisungen, Anweisungen gegen die Prüfung selbst (`META-TAMPER`), Zugangsdaten plus Netzwerkzugriff in einem Skript (`COMBO-EXFIL`), Binärdateien, Symlinks, eine Datei, die der Scanner nicht verarbeiten konnte (`SCAN-ERROR`) |
| MEDIUM | Braucht eine Entscheidung des Nutzers. | Hooks und Install-Skripte, Autostart-Konfiguration (`AUTORUN-*`), MCP-Server ohne feste Version (`MCP-UNPINNED`), ein Skill-Name, der mit einem installierten Skill kollidiert (`FM-NAME-COLLISION`) |
| LOW | Gut zu wissen, allein selten ein Problem. | Abgekoppelte Hintergrundprozesse (`CODE-BACKGROUND`), Netzwerkzugriff plus Prozessstart (`COMBO-FETCH-EXEC`) |
| INFO | Inventar, keine Wertung. | Eine Datei enthält Code (`CODE-FILE`), ein deklarierter MCP-Server (`MCP-SERVER`), ein verschachteltes Archiv, das entpackt und mitgeprüft wurde (`ARCHIVE-SCANNED`) |

Die vollständige Liste, was auf welcher Stufe als Befund zählt, steht in
SKILL.md.

Exit-Codes des Scanners:

| Code | Bedeutung |
|------|-----------|
| 0 | Kein Befund über LOW |
| 1 | Mindestens ein MEDIUM-Befund |
| 2 | Mindestens ein HIGH-Befund |

Der Exit-Code wird aus allen Befunden berechnet. `--min-severity` filtert
nur die Textausgabe. Eine Datei, an der eine Prüfung abstürzt, wird zu einem
HIGH-Befund (`SCAN-ERROR`). Ein teilweise gescheiterter Scan kann also nicht
mit 0 enden.

## Den Scanner allein ausführen

Voraussetzungen: Python 3.9 oder neuer, keine Pakete. Für jeden Aufruf
gelten zwei Regeln:

- Die Skripte mit `python3 -I` starten. Im isolierten Modus lädt Python
  keine Module aus dem aktuellen Verzeichnis oder dem Verzeichnis des
  Skripts. Eine präparierte `json.py` im geprüften Paket wird so nicht
  importiert.
- Ein Arbeitsverzeichnis ausserhalb des geprüften Ordners wählen.

```bash
cd "$(mktemp -d)"
S=/path/to/skillbouncer/skills/skillbouncer/scripts

# Optional: Namen der bereits installierten Skills für die Kollisionsprüfung.
python3 -I $S/skillbouncer_baseline.py snapshot --auto --out snap.json
python3 -I $S/skillbouncer_baseline.py names --snapshot snap.json --out names.txt

python3 -I $S/skillbouncer_scan.py /path/to/package \
    --json scan.json --min-severity MEDIUM --known-names names.txt
```

Der Pfad darf ein Ordner mit vielen Skills sein, ein einzelner Skill-Ordner
oder ein ZIP-basiertes Archiv (`.zip`, `.skill`, `.plugin`, `.whl`, `.vsix`,
`.xpi`, `.egg`). Archive werden sicher in einen temporären Ordner entpackt,
der danach gelöscht wird. Verschachtelten ZIP-basierten Archiven folgt der
Scanner zwei Ebenen tief. Andere Archivformate wie `.tar.gz` oder `.7z`
meldet er als `FS-NESTED-ARCHIVE` und entpackt sie nicht.

Optionen:

| Option | Wirkung |
|--------|---------|
| `--json FILE` | Schreibt zusätzlich alle Befunde, das Skript-Inventar und das Domain-Inventar als JSON. |
| `--min-severity {INFO,LOW,MEDIUM,HIGH}` | Niedrigste Stufe, die im Textbericht erscheint. Standard `LOW`. |
| `--max-per-rule N` | Zeilen pro Regel und Skill im Textbericht. Standard 8. Das JSON enthält alle Treffer. |
| `--known-names FILE` | Datei mit einem installierten Skill-Namen pro Zeile. Ein geprüfter Skill, der einen davon wiederverwendet, wird gemeldet. |
| `--no-builtin-names` | Überspringt die eingebaute Liste der mitgelieferten Skill-Namen. Zu verwenden, wenn die mitgelieferten Skills selbst geprüft werden. |
| `--version` | Gibt die Scanner-Version aus. |

Achte im Kopf des Berichts auf die Zahl bei «Files scanned». Ein Pfad, den
es nicht gibt, ein defektes Archiv oder ein leerer Ordner endet in einem
HIGH-Befund (`SCAN-TARGET`, `ARCHIVE-ERROR`, `SCAN-EMPTY`) und Exit-Code 2,
nie in einem sauberen Bericht. Dasselbe gilt für Inhalt, den der Scanner
nicht vollständig lesen konnte: eine Datei über 5 MB (`FS-TRUNCATED`), eine
Binärdatei hinter einer Text- oder Code-Endung (`FS-UNKNOWN-BIN`), ein
Archiveintrag, der sich nicht entpacken lässt, ein Ordner, der sich nicht
auflisten lässt (`IO-ERROR`). Bilder, Schriften und andere Binärdateien
werden nach lesbarem Text durchsucht, und die Regeln laufen über diesen
Text: Eine Shell führt Skriptzeilen in einer Datei aus, egal was deren
erste Bytes sagen. Auch Aufruffehler und interne Fehler enden mit 2. Die Ausschnitte im Bericht sind Zitate aus dem geprüften, nicht
vertrauenswürdigen Inhalt. Prüft skillbouncer sich selbst, meldet es seine
eigenen Suchmuster und seine Dokumentation als HIGH. Das ist erwartet.

Das Baseline-Skript `skillbouncer_baseline.py` hat fünf Unterbefehle:

| Unterbefehl | Zweck |
|-------------|-------|
| `snapshot --auto [--root DIR ...] --out snap.json` | Findet die Installationsorte dieser Sitzung und erfasst einen Hash pro Datei und Einheit. Statt `--auto` können Ordner direkt angegeben werden. Jede Datei zählt, auch `.git` und `__pycache__`; ein als Symlink installierter Skill oder ein solches Plugin wird am Ziel erfasst. Endet mit 2, wenn ein angegebener Ordner fehlt, kein Skill oder Plugin gefunden wird oder sich etwas nicht lesen lässt. |
| `export --snapshot snap.json --out-dir DIR [--only ID ...] [--verdict V]` | Schreibt pro Einheit ein Baseline-Dokument als JSON in einen Ordner. `--only` ohne ID ist ein Fehler. |
| `diff --baseline-dir DIR --snapshot snap.json --out diff.json` | Vergleicht einen Snapshot mit den Baseline-Dokumenten in einem Ordner. Endet mit 1, wenn etwas zu prüfen ist: neue, geänderte oder entfernte Einheiten, ein Symlink auf Inhalt ausserhalb des Snapshots oder unveränderte Einheiten, die zuletzt mit einer anderen Scanner-Version geprüft wurden. Sonst endet es mit 0, bei einem Fehler mit 2. Einheiten mit PENDING werden aufgelistet, ohne den Exit-Code zu ändern. |
| `names --snapshot snap.json --out names.txt` | Schreibt die Namen aller installierten Skills, einen pro Zeile, für `--known-names`: Ordnernamen und die Namen, die die SKILL.md-Dateien angeben. |
| `selfcheck (--expect HASH:PATH[,HASH:PATH ...] \| --expect-file FILE \| --print)` | Bildet die Hashes beider Skripte und der SKILL.md und vergleicht sie mit den erwarteten. Endet mit 2 bei einer Abweichung, einem fehlenden Hash oder einem Hash für eine andere Datei. `--print` zeigt die aktuellen Hashes. |

## Die monatliche geplante Aufgabe einrichten

Modus B läuft als geplante Aufgabe: einmal im Monat eine frische
Claude-Sitzung, meist ohne dass jemand zuschaut. Der Auftrag der Aufgabe
muss zwei Dinge enthalten:

1. **Wo der Baseline-Speicher liegt** (siehe nächster Abschnitt). Ohne diese
   Angabe muss Claude nachfragen und kann nicht unbeaufsichtigt laufen.
2. **Die drei Selfcheck-Hashes**: SHA-256 von `skillbouncer_scan.py`,
   `skillbouncer_baseline.py` und `SKILL.md`.

Erzeuge die Hashes aus dem Quellstand, den du geprüft hast, im
Wurzelverzeichnis des Repositorys (oder in der entpackten Plugin-Datei, die
gleich aufgebaut ist):

```bash
sha256sum skills/skillbouncer/scripts/*.py skills/skillbouncer/SKILL.md
```

Wo `sha256sum` fehlt, liefert `shasum -a 256` dasselbe Format. Ein Auftrag
kann so aussehen:

```text
Run the skillbouncer monthly check (mode B, references/monthly-run.md).

Baseline store: <Ort der Artifact-Datenbank oder des privaten Repositorys>

Selfcheck hashes (SHA-256):
<hash>  skillbouncer_scan.py
<hash>  skillbouncer_baseline.py
<hash>  SKILL.md
```

**Erneuere die Hashes nach jedem Update von skillbouncer.** Sie ändern sich
mit jeder Version. Mit veralteten Hashes hält der nächste Lauf beim
Selfcheck an und meldet eine Abweichung. Genau dafür ist er gebaut.

Warum die Hashes im Auftrag stehen: Die installierten Skripte liegen in
einem Ordner, in den andere Plugins derselben Sandbox schreiben können. Eine
Prüfung, die ihre Sollwerte vom selben Ort liest, beweist nichts. Der
Auftrag der Aufgabe wird ausserhalb der Sandbox gespeichert. Ein
manipulierter Scanner kann also nicht auch noch passende Hashes liefern.

Dauerhafter Vorbehalt: Die Hooks aller installierten Plugins sind bereits
gelaufen, wenn die monatliche Sitzung beginnt. Ein kompromittiertes Plugin
hatte seine Gelegenheit, bevor die Prüfung anfing. Der Lauf kann zeigen, was
sich auf der Platte geändert hat. Er kann nicht zeigen, dass die Sitzung
unberührt ist. Jedes Ergebnis trägt diesen Vorbehalt, und ein neuer oder
geänderter Hook wird immer als PENDING markiert, egal wie er aussieht.

Bei leerem Referenzstand zählt jede installierte Einheit als neu und wird
einmal geprüft.

## Baseline-Speicher

Wo der Referenzstand liegt, entscheidet der Nutzer:

- **Standardvorschlag:** eine Claude-Artifact-Datenbank mit den Collections
  `baseline` (ein Dokument pro Einheit) und `runs` (ein Dokument pro
  Prüflauf).
- **Alternative:** ein JSON-Verzeichnis in einem privaten Repository, eine
  Datei pro Einheit unter `baseline/` und eine pro Lauf unter `runs/`.

Die Skripte sprechen nie mit einem Speicher. Sie lesen und schreiben nur
JSON-Verzeichnisse: `export` schreibt pro Einheit ein Dokument in einen
Ordner, `diff` liest einen solchen Ordner. Die Dokumente zwischen diesem
Ordner und dem Speicher zu bewegen ist Claudes Aufgabe während des Laufs.

Ein Baseline-Dokument enthält Hashes, Version, Quelle und Urteil, nicht den
geprüften Inhalt. Ein Verzeichnis `node_modules/<package>/` wird als ein
gemeinsamer Hash gespeichert, damit die Dokumente klein bleiben. Eine
geänderte Abhängigkeit wird deshalb als ganzer Ordner gemeldet.

## Bekannte Grenzen

- **Semantische Manipulation in flüssiger Prosa fällt nur beim Lesen auf.**
  Text, der den Assistenten ohne jedes Signalwort lenkt, kommt am Scanner
  vorbei. Deshalb verlangt der Ablauf, jede Datei vollständig zu lesen.
- **Injection-Formulierungen sind nur für wenige Sprachen abgedeckt.**
  «Ignoriere deine Anweisungen» wird auf Englisch, Deutsch, Französisch,
  Spanisch und Italienisch erkannt (`INJ-OVERRIDE`, `INJ-OVERRIDE-DE`,
  `-FR`, `-ES`, `-IT`), «verschweige das dem Nutzer» auf Englisch und
  Deutsch (`DECEPT-HIDE`, `DECEPT-HIDE-DE`). Die übrigen Injection-Regeln
  sind englisch. Andere Sprachen sind nicht abgedeckt.
- **Keine Analyse durch Ausführen.** Verhalten, das sich erst zur Laufzeit
  zeigt (später nachgeladener Code, Verschleierung, die sich statisch nicht
  auflösen lässt), wird nicht beobachtet. Der Ablauf behandelt ein solches
  Paket als nicht prüfbar und sperrt es.
- **Die Erkennung von Fähigkeiten beruht auf Regex und lässt sich umgehen.**
  Das Skript-Inventar zeigt, was die Muster erkennen. Ungewöhnliche
  Bibliotheken, zusammengesetzte Strings und Umwege können eine Fähigkeit
  oder ein Netzwerkziel verbergen.
- **Kombinationen auf Paketebene sind ein Hinweis, kein Beweis.**
  `COMBO-PKG-*` sagt, dass eine Datei etwas Sensibles liest und eine andere
  Netzwerkzugriff hat. Ob Daten zwischen ihnen fliessen, muss beim Lesen
  verfolgt werden.
- **Der Monatslauf sieht Änderungen auf der Platte, nicht was schon gelaufen
  ist.** Er sieht auch nur die Orte, an denen er installierte Skills und
  Plugins findet. Code, den ein Plugin zur Laufzeit nachlädt, oder ein
  MCP-Server, den es aus einem Paket ohne feste Version startet, liegt
  ausserhalb des Referenzstands.

## Entwicklung

Der Scanner bleibt eine einzelne Datei, nur Standardbibliothek, mit Syntax,
die auf Python 3.9 läuft. Die Prüfungen laufen im Wurzelverzeichnis des
Repositorys:

```bash
python3 -m py_compile skills/skillbouncer/scripts/*.py
python3 -I tests/run_tests.py

python3 -I tests/make_fixtures.py tests/fixtures-out
python3 -I tests/verify_prefilter.py skills/skillbouncer/scripts/skillbouncer_scan.py tests/fixtures-out
```

`tests/run_tests.py` baut beide Fixture-Sätze in einen temporären Ordner,
lässt Scanner und Baseline-Skript darüber laufen und vergleicht die
Ergebnisse mit den erwarteten Regel-IDs pro Fixture.
Der Lauf dauert etwa eine halbe Minute. Den grössten Teil davon brauchen
Eingaben, die den Scanner früher blockiert haben.
`tests/verify_prefilter.py` belegt, dass der schnelle Vorfilter des Scanners
über die ganze Datei keinen Zeilentreffer verliert. Die letzte Zeile muss
auf `lost 0` enden. `tests/profile_rules.py <scanner.py> <folder>` zeigt,
welche Regeln am meisten Zeit kosten.

Fixtures sind inerter Text. Nichts darin wird ausgeführt, Hosts verwenden
`.invalid` oder `.example`, und «Binärdateien» bestehen aus Magic Bytes und
Nullen. `tests/fixtures-out/` wird erzeugt und von git ignoriert.

### Eine Regel hinzufügen

1. Ein Tupel `(id, severity, description, regex, code_only)` in `RULES` in
   `skills/skillbouncer/scripts/skillbouncer_scan.py` ergänzen. Die ID muss
   eindeutig sein. `code_only` auf `True` setzen, wenn das Muster in Prosa
   Fehlalarme auslösen würde.
2. Ein inertes Fixture, das die Regel auslöst, in `tests/make_fixtures.py`
   ergänzen, oder in `tests/make_evasion_fixtures.py`, wenn es eine
   Umgehungstechnik nachbildet.
3. Die Regel-ID bei den erwarteten IDs dieses Fixtures in
   `tests/run_tests.py` eintragen und prüfen, dass die harmlosen Fixtures
   (`benign-api`, `ev-benign`, `ev-benign-meta`) weiterhin keinen MEDIUM-
   oder HIGH-Befund
   haben.
4. Die Tests und `verify_prefilter.py` ausführen.

Bestehende Regexe bleiben, wie sie sind, ausser die Änderung gilt genau
dieser Regel. Sie sind an einem grossen Korpus echter Skills abgestimmt.

Die Laufzeit zählt, weil ein Scan Tausende Dateien umfasst. Zwei Lehren
stecken im Scanner:

- Kein `re.IGNORECASE` über ganze Dateien. Es macht Pythons Regex-Engine
  etwa viermal langsamer. Der Scanner schreibt deshalb jede Datei einmal
  klein und durchsucht sie mit einer kleingeschriebenen Kopie jeder Regel,
  bevor er Zeile für Zeile prüft. Siehe die Kommentare bei `lower_pattern`
  und `prefilter_rx`.
- Nur begrenzte Quantoren. `[^\n]{0,200}` schreiben, nicht `[^\n]*`: Ein
  unbegrenzter Quantor wird auf minifizierten Zeilen von einem Megabyte
  quadratisch. Aus demselben Grund werden HTML-Kommentare mit `str.find`
  gesucht und nicht mit einem Regex. Siehe den Kommentar bei
  `iter_html_comments`.

Weitere Lehren dieser Art, jede mit einem Fehlalarm oder einem hängenden
Scan bezahlt, stehen in `docs/development-notes.md`. Das Sicherheitsreview,
das zu Version 1.2.0 geführt hat, steht in
`docs/security-review-2026-11.md`.

## Lizenz

MIT. Siehe `LICENSE`.
