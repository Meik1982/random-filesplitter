# Fish completion for rfs (random-filesplitter v3.0.0)

# Disable file completions by default unless requested
complete -c rfs -f

# Global Options
complete -c rfs -s h -l help -d "Hilfe anzeigen"
complete -c rfs -s V -l version -d "Version anzeigen"
complete -c rfs -s f -l force -d "Existierende Zieldateien überschreiben"
complete -c rfs -s q -l quiet -d "Stummschalten (nur Fehler)"
complete -c rfs -l silent -d "Stummschalten (nur Fehler)"
complete -c rfs -l json -d "Maschinenlesbare NDJSON-Telemetrie auf stderr"
complete -c rfs -l direct -d "Direct I/O: Kernel Page-Cache umgehen"
complete -c rfs -l token -l rnd -d "Anti-Forensik: Hex-Tokens (.<rnd>.rfs) statt Nummern"
complete -c rfs -s b -l benchmark -d "Hardware-Benchmark ausführen"
complete -c rfs -s e -l entropy -l entropy-test -d "Entropiediagnose ausführen"
complete -c rfs -s a -l analyze -r -F -d "NIST SP 800-22 Datei-Entropieanalyse"
complete -c rfs -s v -l verify -l check -d "Integrität im RAM prüfen"

# Subcommands
complete -c rfs -n "__fish_use_subcommand" -a split -d "Datei in N Rausch-Teile aufteilen"
complete -c rfs -n "__fish_use_subcommand" -a restore -d "Originaldatei aus N Teilen wiederherstellen"
complete -c rfs -n "__fish_use_subcommand" -a verify -d "Integrität im RAM prüfen"
complete -c rfs -n "__fish_use_subcommand" -a decoy -d "Köderdateien (Decoys) erzeugen"
complete -c rfs -n "__fish_use_subcommand" -a benchmark -d "Hardware-Benchmark ausführen"
complete -c rfs -n "__fish_use_subcommand" -a entropy -d "Entropiediagnose ausführen"
complete -c rfs -n "__fish_use_subcommand" -a analyze -d "Datei analysieren"

# split options
complete -c rfs -n "__fish_seen_subcommand_from split" -s n -l parts -x -a "2 3 4 5 8 16" -d "Anzahl der Teile"
complete -c rfs -n "__fish_seen_subcommand_from split" -s d -l decoys -x -a "1 2 3 4 5 10" -d "Zusätzliche Köderdateien"
complete -c rfs -n "__fish_seen_subcommand_from split" -s B -l block-size -x -a "64K 256K 1M 4M 8M 16M" -d "Puffergröße"
complete -c rfs -n "__fish_seen_subcommand_from split" -s o -l output -r -F -d "Präfix oder Ausgabepfad"
complete -c rfs -n "__fish_seen_subcommand_from split" -F

# decoy options
complete -c rfs -n "__fish_seen_subcommand_from decoy" -s c -l count -x -a "1 2 3 4 5 10" -d "Anzahl der Köderdateien"
complete -c rfs -n "__fish_seen_subcommand_from decoy" -s s -l size -x -a "64K 1M 10M 100M 1G" -d "Explizite Dateigröße"
complete -c rfs -n "__fish_seen_subcommand_from decoy" -s t -l template -r -F -d "Musterdatei (Rohdatei +60B oder RFS 1:1)"
complete -c rfs -n "__fish_seen_subcommand_from decoy" -s B -l block-size -x -a "64K 256K 1M 4M 8M 16M" -d "Puffergröße"
complete -c rfs -n "__fish_seen_subcommand_from decoy" -s o -l output -r -F -d "Präfix oder Dateipfad"
complete -c rfs -n "__fish_seen_subcommand_from decoy" -F

# restore options
complete -c rfs -n "__fish_seen_subcommand_from restore" -s B -l block-size -x -a "64K 256K 1M 4M 8M 16M" -d "Puffergröße"
complete -c rfs -n "__fish_seen_subcommand_from restore" -s o -l output -r -F -d "Zieldatei (oder - für stdout)"
complete -c rfs -n "__fish_seen_subcommand_from restore" -F

# verify options
complete -c rfs -n "__fish_seen_subcommand_from verify" -s B -l block-size -x -a "64K 256K 1M 4M 8M 16M" -d "Puffergröße"
complete -c rfs -n "__fish_seen_subcommand_from verify" -F

# analyze options
complete -c rfs -n "__fish_seen_subcommand_from analyze" -F
