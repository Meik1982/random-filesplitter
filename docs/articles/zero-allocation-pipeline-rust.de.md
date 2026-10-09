# Fallstudie: Entwurf einer allokationsfreien Pipeline mit SIMD-XOR und mlock in Rust

> **Zielgruppe:** r/rust / Fachpublikum (Technischer Deep Dive)  
> **Repository:** https://github.com/Meik1982/random-filesplitter  
> **Lizenz:** LGPL v3

---

Beim Bau von I/O-Streaming-Pipelines mit hohem Durchsatz in Rust, die Gigabytes an sensiblen Daten verarbeiten, stoßen Standardmuster (wie das ständige Neuzuordnen von Puffern pro Lesevorgang oder das Überlassen des Speichermanagements an das Betriebssystem) schnell an architektonische Grenzen.

In den letzten vier Monaten habe ich `rfs` (random-filesplitter) entwickelt – ein Werkzeug zur Aufteilung von Dateien in informationstheoretische One-Time-Pad-Shares ($P = C_1 \oplus \dots \oplus C_N$) mit glaubhafter Abstreitbarkeit (*Plausible Deniability*). In dieser Domäne treten zwei spezifische Probleme auf:

1. **Anti-forensische Speicherlecks:** Wenn Zwischenpuffer oder Klartextströme in Swap-Partitionen oder Hibernation-Dateien ausgelagert werden, wird flüchtiges Nullen im RAM (`ZeroizeOnDrop` oder `slice.zeroize()`) komplett umgangen.
2. **Gegendruck bei Multi-Mountpoints:** Wenn $N$ separate Shares über voneinander unabhängige Datenträger geschrieben werden (z. B. langsame USB-Sticks neben schnellen NVMe-SSDs), blockieren sequentielle Schreibschleifen die gesamte Kryptopipeline.

Nachfolgend wird analysiert, wie wir diese Engpässe bei Concurrency, SIMD und Speicherfixierung in Rust ohne eine einzige Heap-Allokation im Hot-Loop gelöst haben.

---

### 1. Allokationsfreie Nebenläufigkeit: Begrenztes Triple-Buffering

**Das Konzept:**  
Man stelle sich eine industrielle Verarbeitungsanlage vor, die einen riesigen Rohstoffberg verarbeitet. Der ineffiziente Weg wäre, für jede Schaufel einen neuen Eimer zu bauen, ihn einmal zu benutzen und wegzuwerfen. Stattdessen nutzen wir ein Förderband mit genau drei permanenten Behältern, die kontinuierlich drei Stationen durchlaufen (Lesen, Verarbeiten, Schreiben). Das System wird unabhängig von der Gesamtmenge niemals überlastet.

**Die technische Umsetzung:**  
Die Architektur ist in drei entkoppelte Stufen unterteilt:
- **Stufe 1 (Reader):** Sequentielles Einlesen von Datenträger oder `stdin`.
- **Stufe 2 (Crypto Worker):** ChaCha20-Zufallsstromerzeugung und SIMD-XOR.
- **Stufe 3 (Parallele Writer):** Fanout auf $N$ unabhängige Worker-Threads.

Um Allokations-Overhead zwischen Threads zu eliminieren, wird ein fester Pool von Speicherblöcken über `crossbeam_channel::bounded` vorab reserviert:

```rust
// Vereinfachte Architekturskizze
pub struct BufferSlot {
    pub data: Vec<u8>,
}

// Fester Ring-Pool: genau 3 Slots aktiv in der Pipeline
let (free_tx, free_rx) = crossbeam_channel::bounded::<BufferSlot>(3);
let (work_tx, work_rx) = crossbeam_channel::bounded::<WorkItem>(3);

// Pool einmalig vorab initialisieren
for _ in 0..3 {
    free_tx.send(BufferSlot { data: vec![0u8; BLOCK_SIZE] }).unwrap();
}
```

**Funktionsweise:**
1. Der Reader holt sich einen Slot aus `free_rx`, liest Blockdaten von der Platte und sendet ihn an `work_tx`.
2. Der Crypto Worker empfängt den Puffer, generiert ChaCha20-Zufall, berechnet SIMD-XOR in-place und verteilt Slice-Referenzen an die Writer.
3. Sobald alle Writer-Threads ihre Schreibvorgänge für diesen Block abgeschlossen haben, wird derselbe `BufferSlot` genullt und in `free_tx` zurückgeführt.

**Ergebnis:** Selbst bei 100+ GB großen Dateien bleibt der Speicherverbrauch strikt $O(1)$ auf $\approx 3 \times \text{BLOCK\_SIZE}$ fixiert. Heap-Allokationen und Allokator-Konflikte im Streaming-Loop werden vollständig eliminiert.

---

### 2. Swap-Resilienz mit sicherem RAII `mlock`

**Das Konzept:**  
Wenn der Arbeitsspeicher (RAM) knapp wird, lagert das Betriebssystem heimlich Daten auf die Festplatte (Swap) aus. Für ein Anti-Forensik-Werkzeug ist das verheerend. Es ist, als würde man ein streng geheimes Dokument in einem Tresor lesen, aber ein Wachmann macht heimlich eine Kopie und legt sie draußen in eine offene Altpapiertonne. Wir weisen den Kernel an, die sensiblen Daten im physischen RAM-Tresor festzuschließen.

**Die technische Umsetzung:**  
Flüchtiges Nullen im RAM ist wirkungslos, wenn der Kernel Seiten auf die Platte auslagert. Puffer müssen über POSIX `mlock` im physischen RAM verankert werden. Das sichere Kapseln von `libc::mlock` in Rust erfordert gültige virtuelle Adressen und einen Graceful Fallback bei Beschränkung von `RLIMIT_MEMLOCK` (`ulimit -l`):

```rust
/// Sperrt einen Byte-Slice über libc::mlock im physischen RAM.
/// Liefert true bei Erfolg oder false bei Systembeschränkungen.
pub fn lock_memory(slice: &[u8]) -> bool {
    #[cfg(unix)]
    {
        if slice.is_empty() {
            return true;
        }
        // SAFETY: `slice.as_ptr()` zeigt auf einen gültigen, allokierten Slice der Länge `slice.len()`.
        // `libc::mlock` liest Zeiger und Bytezahl, um virtuelle Seiten im RAM zu sperren.
        let res = unsafe { libc::mlock(slice.as_ptr() as *const libc::c_void, slice.len()) };
        res == 0
    }
    #[cfg(not(unix))]
    {
        let _ = slice;
        false
    }
}

/// Entsperrt einen zuvor gesperrten Byte-Slice über libc::munlock.
pub fn unlock_memory(slice: &[u8]) {
    #[cfg(unix)]
    {
        if !slice.is_empty() {
            // SAFETY: `slice.as_ptr()` zeigt auf einen gültigen Speicherbereich der Länge `slice.len()`.
            unsafe { libc::munlock(slice.as_ptr() as *const libc::c_void, slice.len()); }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = slice;
    }
}
```

Wir vermeiden manuelle Zeigerhaltung oder Lifetime-Probleme: Wir sperren und entsperren direkt sichere Slice-Referenzen auf den vorallokierten Ringpuffer-Slots.

---

### 3. SIMD-XOR: Auto-Vektorisierung vs. handgeschriebene Intrinsics

**Das Konzept:**  
Daten Zeichen für Zeichen mit Zufallszahlen zu verschleiern dauert ewig – wie das Ausheben eines Grabens mit einem Teelöffel. Wir formatieren unsere Daten so, dass die CPU ihre Baggerschaufel nutzen kann (große 64-Byte-Blöcke in einem einzigen Taktzyklus verarbeiten), sodass die Daten so schnell fließen, wie die SSD liefern kann.

**Die technische Umsetzung:**  
Für die $N$-fache Kombination ($P = C_1 \oplus \dots \oplus C_N$) muss der CPU-Durchsatz die Busgeschwindigkeit übersteigen. Statt architekturabhängiger Assembler-Befehle nutzen wir LLVMs Auto-Vektorisierung über eine entrollte 64-Byte-Wort-Schleife:

```rust
#[inline(always)]
pub fn xor_in_place(dest: &mut [u8], src: &[u8]) {
    assert_eq!(dest.len(), src.len());
    let (d_chunks, d_tail) = dest.as_chunks_mut::<64>();
    let (s_chunks, s_tail) = src.as_chunks::<64>();

    for (d, s) in d_chunks.iter_mut().zip(s_chunks) {
        let d_u64: &mut [u64; 8] = bytemuck::cast_mut(d);
        let s_u64: &[u64; 8] = bytemuck::cast_ref(s);
        d_u64[0] ^= s_u64[0];
        d_u64[1] ^= s_u64[1];
        d_u64[2] ^= s_u64[2];
        d_u64[3] ^= s_u64[3];
        d_u64[4] ^= s_u64[4];
        d_u64[5] ^= s_u64[5];
        d_u64[6] ^= s_u64[6];
        d_u64[7] ^= s_u64[7];
    }
    for (d, s) in d_tail.iter_mut().zip(s_tail) {
        *d ^= *s;
    }
}
```

**Benchmark-Ergebnisse (x86_64, AVX2):**  
- Standard Byte-für-Byte Iterator-XOR: $\approx 1{,}1 \text{ GB/s}$
- 64-Byte entrollter Chunk-XOR: **$\approx 4{,}02 \text{ GB/s}$**  
- Hardware-Limit: Vollständige Sättigung des Speicherbusses. 100 % Safe Rust ohne Zeiger-Arithmetik.

---

### 4. Paralleler Disk-Fanout & Cache-Management (`fadvise`)

**Das Konzept:**  
Das gleichzeitige Schreiben auf ein schnelles internes Laufwerk und einen langsamen USB-Stick bremst das Gesamtsystem normalerweise auf das Tempo des Sticks herunter. Durch entkoppelte Worker erhält das schnelle Laufwerk seine Daten sofort, während der Stick in seinem eigenen Rhythmus schreibt. Zusätzlich weisen wir den Kernel an, den Cache geschriebener Daten sofort zu leeren, damit der RAM nicht mit Gigabytes an Rauschen geflutet wird.

**Die technische Umsetzung:**  
Über entkoppelte Scoped Threads (`std::thread::scope`) mit begrenzten Channels schreibt jeder Writer mit der nativen Geschwindigkeit seines Speichermediums. Um den Linux Page-Cache nicht mit Terabytes an Rauschen zu belasten, steuern wir den Kernel via `libc::posix_fadvise`:

- `POSIX_FADV_SEQUENTIAL`: Signalisiert aggressives Vorauslesen für den Reader.
- `POSIX_FADV_DONTNEED`: Entfernt geschriebene Seiten nach dem Flush direkt aus dem Cache, damit der RAM für aktive Anwendungen frei bleibt.

---

### Erkenntnisse & Roadmap

- **Keine Allokationen:** Vorallokierte Bounded Channels verhindern GC- und Allokations-Stalls vollständig.
- **Tiefenstaffelung:** Die Kombination aus `mlock`, `slice.zeroize()` und `fadvise` garantiert strenge Speicherhygiene.
- **Strikt minimales Unsafe:** Von $\approx 3{,}800$ Zeilen Quellcode enthalten genau 4 Zeilen ein `unsafe` – strikt beschränkt auf Kernel-Systemaufrufe (`mlock`/`munlock` und `fadvise`), vollständig mit Safety-Invarianten dokumentiert. Sämtliche Krypto-, Streaming- und SIMD-Logik ist 100 % Safe Rust.

Als nächster Meilenstein ist eine schlanke native Desktop-GUI (Slint/Iced, Drag & Drop) für Anwender ohne Terminal-Fokus geplant.

Quellcode und Concurrency-Tests (LGPL v3):  
**https://github.com/Meik1982/random-filesplitter**
