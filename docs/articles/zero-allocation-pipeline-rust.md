# Case Study: Designing a Zero-Allocation 3-Stage Pipeline with SIMD-XOR and POSIX Memory Locking (mlock) in Rust

> **Target Audience:** r/rust (Technical Article / Deep Dive)  
> **Repository:** https://github.com/Meik1982/random-filesplitter  
> **License:** LGPL v3

---

When building high-throughput I/O pipelines in Rust that handle gigabytes of data under strict security constraints, standard idiomatic patterns (like allocating fresh buffers per read or letting the OS manage memory pages) can quickly hit architectural walls.

Over the past four months, I’ve been developing `rfs` (random-filesplitter), a tool designed to split files into information-theoretic One-Time-Pad shares ($P = C_1 \oplus \dots \oplus C_N$) with plausible deniability. In this domain, two unique engineering problems emerge:

1. **Anti-Forensic Memory Leaks:** If intermediate OTP keystreams or plaintext buffers are paged into OS swap partitions or hibernation files, volatile zeroization (`ZeroizeOnDrop`) is completely bypassed.
2. **Multi-Mountpoint Backpressure:** Writing $N$ separate multi-gigabyte shares across physically independent flash drives (e.g., slow USB sticks alongside fast NVMe drives) causes sequential writers to stall the entire crypto pipeline.

Below is a breakdown of how we solved these concurrency, SIMD, and memory-locking bottlenecks in Rust without a single heap allocation in the hot streaming loop.

---

### 1. Zero-Allocation Concurrency: Bounded Triple-Buffering

The architecture is split into three decoupled stages:
- **Stage 1 (Reader):** Sequential ingestion from disk or `stdin`.
- **Stage 2 (Crypto Worker):** ChaCha20 keystream generation and multi-way SIMD-XOR.
- **Stage 3 (Parallel Writers):** Fanout to $N$ independent worker threads.

To eliminate heap allocator overhead across threads, we pre-allocate a fixed pool of memory blocks wrapped in `crossbeam_channel::bounded`:

```rust
// Simplified architecture sketch
pub struct BufferSlot {
    pub data: Vec<u8>,
}

// Fixed ring pool: only 3 slots in-flight across stages
let (free_tx, free_rx) = crossbeam_channel::bounded::<BufferSlot>(3);
let (work_tx, work_rx) = crossbeam_channel::bounded::<WorkItem>(3);

// Initialize pool once upfront
for _ in 0..3 {
    free_tx.send(BufferSlot { data: vec![0u8; BLOCK_SIZE] }).unwrap();
}
```

**How the lifecycle works:**
1. The Reader grabs a pre-allocated `BufferSlot` from `free_rx`, reads block bytes from disk, and forwards it to `work_tx`.
2. The Crypto Worker receives the buffer, generates ChaCha20 random streams, computes SIMD-XOR in-place, and fans out slice references to the disk writers.
3. Once all writer threads finish their `pwrite`/`write_all` calls for that block, the exact same `BufferSlot` is zeroized and returned back into `free_tx`.

**Result:** Even when processing 100+ GB files, total memory usage remains pinned at exactly $\approx 3 \times \text{BLOCK\_SIZE}$, and allocator contention is zero.

---

### 2. Swap-Resilience with Safe RAII `mlock`

In security-critical applications, volatile zeroization is useless if the kernel decides to swap dirty memory pages to disk. To prevent this, physical pages must be locked in RAM using POSIX `mlock`.

Wrapping `libc::mlock` safely in Rust requires handling two challenges:
1. `mlock` requires valid virtual memory addresses and must strictly avoid page-fault crashes.
2. Many user environments enforce strict `RLIMIT_MEMLOCK` (`ulimit -l`), causing hard errors if memory limits are exceeded.

We implemented a cross-platform memory locker with graceful degradation:

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
            // Lock the virtual address space into physical RAM
            if libc::mlock(ptr as *const libc::c_void, len) == 0 {
                true
            } else {
                eprintln!("[WARN] ulimit -l restricted mlock; proceeding with standard RAM.");
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

### 3. SIMD-XOR Auto-Vectorization vs. Hand-Written Intrinsics

For $N$-way secret combination ($P = C_1 \oplus \dots \oplus C_N$), CPU throughput must exceed bus speed. Rather than maintaining brittle architecture-specific assembly (`avx2`, `neon`), we leveraged LLVM's auto-vectorizer using an unrolled 64-byte word loop:

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

**Benchmark Results (x86_64, AVX2):**
- Standard byte-by-byte iterator XOR: $\approx 1.1 \text{ GB/s}$
- 64-byte unrolled chunk XOR: **$\approx 4.02 \text{ GB/s}$**
- Hardware saturation: Memory-bus bound.

---

### 4. Parallel Disk Fanout & Cache Pressure (`fadvise`)

When fanning out chunks to $N$ target files on different physical flash devices, write speeds vary wildly. If writer threads block, the crypto engine starves.

By spawning independent scoped threads (`std::thread::scope`) communicating over bounded channels, each writer writes at its storage medium's native speed. To avoid polluting the Linux page cache during multi-gigabyte passes, we advise the kernel via `libc::posix_fadvise`:
- `POSIX_FADV_SEQUENTIAL`: Signals continuous readahead.
- `POSIX_FADV_DONTNEED`: Evicts written pages from the page cache immediately after flush, keeping host RAM free for the active working set.

---

### Takeaways & Status
- **Zero Allocations:** Pre-allocating bounded channel slots avoids runtime GC/allocator stalls entirely.
- **Defence-in-Depth:** Combining RAII `mlock` with `ZeroizeOnDrop` guarantees clean volatile memory hygiene even across crashes or cancellations.
- **Roadmap:** The core streaming engine is hardened in v3.0.0 (38/38 tests passing, 0 Clippy warnings). A lightweight native desktop GUI (Slint/iced, Drag & Drop) is planned next for non-terminal workflows.

For those interested in the full implementation details or concurrency tests, the project is open source (LGPL v3):  
https://github.com/Meik1982/random-filesplitter

I’d love to hear how others handle multi-drive fanout backpressure and cross-platform page locking in Rust!
