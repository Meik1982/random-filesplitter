# Fallstudie: Entwurf einer allokationsfreien 3-Stufen-Pipeline mit SIMD-XOR und POSIX Memory Locking (mlock) in Rust

> **Zielgruppe:** r/rust / Fachpublikum (Technischer Deep Dive)  
> **Repository:** https://github.com/Meik1982/random-filesplitter  
> **Lizenz:** LGPL v3

---

Beim Bau von I/O-Streaming-Pipelines mit hohem Durchsatz in Rust, die Gigabytes an Daten unter strengen Sicherheitsanforderungen verarbeiten, stoßen Standardmuster (wie das ständige Neuzuordnen von Puffern pro Lesevorgang oder das Überlassen des Speichermanagements an das Betriebssystem) schnell an architektonische Grenzen.

In den letzten vier Monaten habe ich `rfs` (random-filesplitter) entwickelt – ein Werkzeug zur Aufteilung von Dateien in informationstheoretische One-Time-Pad-Shares ($P = C_1 \oplus \dots \oplus C_N$) mit glaubhafter Abstreitbarkeit (*Plausible Deniability*). In dieser Domäne treten zwei spezifische Probleme auf:

1. **Anti-forensische Speicherlecks:** Wenn Zwischenpuffer oder Klartextströme in Swap-Partitionen oder Hibernation-Dateien ausgelagert werden, wird flüchtiges Nullen im RAM (`ZeroizeOnDrop`) komplett umgangen.
2. **Gegendruck bei Multi-Mountpoints:** Wenn $N$ separate Shares über voneinander unabhängige Datenträger geschrieben werden (z. B. langsame USB-Sticks neben schnellen NVMe-SSDs), blockieren sequentielle Schreibschleifen die gesamte Kryptopipeline.

Nachfolgend wird analysiert, wie wir diese Engpässe bei Concurrency, SIMD und Speicherfixierung in Rust ohne eine einzige Heap-Allokation im Hot-Loop gelöst haben.

---

### 1. Allokationsfreie Nebenläufigkeit: Begrenztes Triple-Buffering

Die Architektur ist in drei entkoppelte Stufen unterteilt:
- **Stufe 1 (Reader):** Sequentielles Einlesen von Datenträger oder `stdin`.
- **Stufe 2 (Crypto Worker):** ChaCha20-Zufallsstromerzeugung und mehrstufiges SIMD-XOR.
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

**Ergebnis:** Selbst bei 100+ GB großen Dateien bleibt der Speicherverbrauch exakt auf $\approx 3 \times \text{BLOCK\_SIZE}$ fixiert.

---

### 2. Swap-Resilienz mit sicherem RAII `mlock`

In sicherheitskritischen Anwendungen nützt flüchtiges Nullen im RAM nichts, wenn der Kernel Speicherseiten auf die Festplatte swapt. Um das zu verhindern, müssen Seiten über POSIX `mlock` im physischen RAM gesperrt werden.

Das sichere Kapseln von `libc::mlock` in Rust erfordert:
1. `mlock` benötigt gültige virtuelle Speicheradressen und muss Page-Fault-Abstürze strikt vermeiden.
2. Viele Umgebungen beschränken `RLIMIT_MEMLOCK` (`ulimit -l`), was bei Überschreitung zu Fehlern führt.

Wir haben einen speicherfixierten Puffer mit Graceful Fallback implementiert:

```rust
pub struct LockedBuffer {
    ptr: *mut u8,
    len: usize,
    is_locked: bool,
}

impl LockedBuffer {
    pub fn new(len: usize) -> Self {
        let mut data = vec![0u8; len];
        let ptr = data.as_mut_ptr();
        
        #[cfg(unix)]
        let is_locked = unsafe {
            if libc::mlock(ptr as *const libc::c_void, len) == 0 {
                true
            } else {
                eprintln!("[WARN] ulimit -l schränkt mlock ein; fahre mit Standard-RAM fort.");
                false
            }
        };
        #[cfg(not(unix))]
        let is_locked = false;

        Self { ptr, len, is_locked }
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.is_locked {
            unsafe {
                libc::munlock(self.ptr as *const libc::c_void, self.len);
            }
        }
    }
}
```

---

### 3. SIMD-XOR Auto-Vektorisierung vs. handgeschriebene Intrinsics

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
- Hardware-Limit: Vollständige Sättigung des Speicherbusses.

---

### 4. Paralleler Disk-Fanout & Cache-Management (`fadvise`)

Beim Schreiben von Chunks auf $N$ Zielmedien schwanken die Geschwindigkeiten stark. Wenn Writer-Threads blockieren, verhungert die Krypto-Engine.

Über entkoppelte Scoped Threads (`std::thread::scope`) mit begrenzten Channels schreibt jeder Writer mit der nativen Geschwindigkeit seines Speichermediums. Um den Linux Page-Cache nicht mit Terabytes an Rauschen zu fluten, steuern wir den Kernel via `libc::posix_fadvise`:
- `POSIX_FADV_SEQUENTIAL`: Signalisiert aggressives Vorauslesen.
- `POSIX_FADV_DONTNEED`: Entfernt geschriebene Seiten nach dem Flush direkt aus dem Cache, damit der RAM für aktive Anwendungen frei bleibt.

---

### Erkenntnisse & Roadmap
- **Keine Allokationen:** Vorallokierte Bounded Channels verhindern GC- und Allokations-Stalls vollständig.
- **Tiefenstaffelung:** Die Kombination aus RAII-`mlock` und `ZeroizeOnDrop` garantiert Speicherhygiene auch bei Programmabbrüchen.
- **Roadmap:** Der Streaming-Kern ist in v3.0.0 gehärtet (38/38 Tests grün, 0 Clippy-Warnungen). Als Nächstes ist eine schlanke native Desktop-GUI (Slint/iced, Drag & Drop) für Anwender ohne Terminal-Fokus geplant.

Quellcode und Concurrency-Tests (LGPL v3):  
https://github.com/Meik1982/random-filesplitter
