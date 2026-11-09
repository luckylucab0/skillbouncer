# Monatslauf: installierte Skills auf Supply-Chain-Änderungen prüfen

Läuft als geplante Aufgabe in einer frischen Sitzung, meist ohne dass der Nutzer zuschaut. Deshalb: keine Rückfragen, Entscheidungen selbst treffen und im Protokoll begründen. Der Referenzstand wird nur für Einheiten aktualisiert, die eindeutig unauffällig sind. Alles andere wartet auf den Nutzer.

## 1. Vorbereiten

- Skillcheck-Übersicht finden: URL aus dem Auftrag, sonst `Artifact` `list` und den Eintrag «Skillcheck» nehmen.
- Arbeitsordner im Scratchpad anlegen; Skripte aus `scripts/` dieses Skills mit `python3 -I` starten.
- `SendUserMessage` laden (ToolSearch), damit das Ergebnis den Nutzer erreicht.

## 2. Referenzstand und aktuellen Stand holen

```bash
# Referenzstand: ArtifactData action=list, collection=baseline, query.limit=1000, out_dir=<work>/baseline
# (bei mehr als 1000 Dokumenten mit next_cursor weiterblättern)

# Kopien vergleichen: claude.ai legt die Skills in mehreren Ordnern ab.
for d in organization private plugins; do diff -rq /mnt/skills/user /mnt/skills/$d; done

python3 -I <skill>/scripts/skillcheck_baseline.py snapshot /mnt/skills/user /mnt/skills/public /mnt/skills/plugin-files --out <work>/snap.json
python3 -I <skill>/scripts/skillcheck_baseline.py diff --baseline-dir <work>/baseline --snapshot <work>/snap.json --out <work>/diff.json
```

Weicht einer der Kopie-Ordner von `user/` ab, ist das ein eigener Befund (MEDIUM): den Ordner zusätzlich in den Snapshot aufnehmen und die abweichenden Dateien prüfen.

Wenn `diff` nichts Neues oder Geändertes meldet (Exit-Code 0): direkt zu Schritt 5, Lauf als «OK, keine Änderungen» eintragen.

## 3. Geänderte Inhalte prüfen

- `to_review` aus `diff.json` ist die Liste aller neuen und geänderten Dateien.
- Scanner nur über die betroffenen Einheiten laufen lassen (`skillcheck_scan.py <einheitsordner> --json ...`) und jeden HIGH/MEDIUM-Treffer im Kontext einordnen.
- Jede Datei aus `to_review` vollständig lesen. Bei mehr als etwa 300 KB auf Review-Agents aufteilen (Auftrag: `references/pruefauftrag.md`, Umfang auf die geänderten Dateien plus zugehörige SKILL.md beschränken).
- Neue oder geänderte Skripte, Hooks, MCP-Konfigurationen und Install-Manifeste (`package.json`, `requirements*.txt`, `setup.py`) vollständig nach `references/skriptanalyse.md` analysieren. Der Referenzstand enthält nur Hashes, nicht den alten Code. Ist die vorige Version greifbar (Git-Historie des Quell-Repos, Diff im Marketplace), das Skript-Inventar beider Stände vergleichen; sonst das Inventar des neuen Stands gegen den Zweck prüfen. Neue Netzwerkziele, neue Fähigkeiten (z. B. erstmals Netzwerk oder Zugriff auf Zugangsdaten) oder neue Abhängigkeiten sind die eigentlichen Warnsignale eines kompromittierten Updates.
- Plausibilität: Passt die Änderung zu einem normalen Update (Versionssprung in `plugin.json` oder `manifest.json`, `updatedAt` neu, Inhalt thematisch passend)? Eine Änderung ohne Versionssprung, eine neue `.mcp.json`, neue Hooks, neue Skripte mit Netzwerkzugriff oder neue Binärdateien sind immer mindestens MEDIUM.
- Entfernte Einheiten nur protokollieren (der Nutzer hat sie vermutlich deinstalliert).

## 4. Urteil und Referenzstand

- **CLEAN/LOW:** `export --snapshot <work>/snap.json --out-dir <work>/neu --verdict CLEAN --only <ids>` und die Dokumente mit ArtifactData `batch` schreiben. Für bestehende Dokumente den `version` aus Schritt 2 als `if_version` mitgeben. Höchstens 50 Einträge und 1 MiB pro Batch.
- **MEDIUM/HIGH:** Referenzstand dieser Einheit nicht ändern. Nur `verdict: "PENDING"` setzen (`update` mit `if_version`), damit die Übersicht «wartet auf Freigabe» zeigt.
- Entfernte Einheiten: Dokument stehen lassen, im Lauf erwähnen. Löschen nur, wenn der Nutzer es bestätigt.

## 5. Protokoll und Nachricht

- `runs`-Eintrag schreiben (Format in SKILL.md), `kind: "Monatslauf"`, `doc_id` z. B. `2026-11-01-monatslauf`.
- Mit `SendUserMessage` kurz melden: Gesamturteil, Zahl der geprüften Änderungen, je auffälliger Einheit ein Satz mit Datei und Zeile, was der Nutzer entscheiden muss. Bei «keine Änderungen» genügt ein Satz.
- Bei HIGH zusätzlich empfehlen, das betroffene Plugin bis zur Klärung unter Anpassen > Plugins zu deaktivieren.
