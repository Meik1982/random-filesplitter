# Case Study: Designing a Zero-Allocation Pipeline with SIMD-XOR and mlock in Rust

> **Target Audience:** r/rust (Technical Deep Dive / Article)  
> **Repository:** https://github.com/Meik1982/random-filesplitter  
> **License:** LGPL v3

*(Hi r/rust! Over the past four months, I’ve been developing a high-throughput, security-focused tool and wanted to share a deep dive into the architectural challenges I encountered—specifically around avoiding heap allocations in hot loops, managing OS page caches, and ensuring volatile memory safety against swapping. I'd love to hear your thoughts on this approach.)*

---

When building high-throughput I/O streaming pipelines in Rust that process gigabytes of sensitive data, standard patterns (like reallocating buffers per read or leaving cache management entirely to the OS) quickly hit architectural limits.

I developed `rfs` (random-filesplitter), a tool designed to split large files into information-theoretic One-Time-Pad shares ($P = C_1 \oplus \dots \oplus C_N$) with plausible deniability. In this domain, two major bottlenecks emerge:

1. **Anti-Forensic Memory Leaks:** If intermediate buffers or plaintext streams are paged out to swap partitions or hibernation files, volatile zeroing in RAM (like `ZeroizeOnDrop` or `slice.zeroize()`) is completely bypassed.
2. **Backpressure Across Multiple Mounts:** When writing $N$ separate shares across independent storage devices (e.g., a slow USB drive alongside a fast NVMe SSD), sequential write loops will stall the entire crypto pipeline.

Below is an overview of how we solved these concurrency, SIMD, and memory-pinning bottlenecks in Rust without a single heap allocation in the hot streaming loop.

---

### 1. Zero-Allocation Concurrency: Bounded Triple-Buffering

**The Concept:**  
Imagine an industrial plant processing a massive pile of raw materials. The inefficient way is building a new container for every scoop, using it once, and throwing it away. Instead, we use a conveyor belt with exactly three permanent containers rotating through three stations (Read, Process, Write). The system is never overloaded, regardless of the total volume.

**The Technical Implementation:**  
The architecture is divided into three decoupled stages:
- **Stage 1 (Reader):** Sequential ingestion from disk or `stdin`.
- **Stage 2 (Crypto Worker):** ChaCha20 keystream generation and SIMD-XOR.
- **Stage 3 (Parallel Writers):** Fanout to $N$ independent worker threads.

To eliminate heap allocation overhead across threads, a fixed pool of memory blocks is pre-allocated using `crossbeam_channel::bounded`:

```rust
// Simplified architecture sketch
pub struct BufferSlot {
    pub data: Vec<u8>,
}

// Fixed ring pool: exactly 3 slots active in the pipeline
let (free_tx, free_rx) = crossbeam_channel::bounded::<BufferSlot>(3);
let (work_tx, work_rx) = crossbeam_channel::bounded::<WorkItem>(3);

// Pre-allocate the pool once upfront
for _ in 0..3 {
    free_tx.send(BufferSlot { data: vec![0u8; BLOCK_SIZE] }).unwrap();
}
```

**How the lifecycle works:**
1. The Reader grabs a pre-allocated `BufferSlot` from `free_rx`, reads block bytes from disk, and forwards it to `work_tx`.
2. The Crypto Worker receives the buffer, generates ChaCha20 random streams, computes SIMD-XOR in-place, and fans out slice references to the disk writers.
3. Once all writer threads finish their `pwrite`/`write_all` calls for that block, the exact same `BufferSlot` is zeroized and returned back into `free_tx`.

**Result:** Even when processing 100+ GB files, memory complexity remains strictly $O(1)$ at exactly $\approx 3 \times \text{BLOCK\_SIZE}$. It completely eliminates heap allocations and allocator contention in the hot streaming loop.

---

### 2. Swap-Resilience via Safe RAII `mlock`

**The Concept:**  
If a computer's short-term memory (RAM) fills up, it secretly writes pages to the hard drive (swap) to make room. For an anti-forensic security tool, this is disastrous. It’s like reading a top-secret document in a bank vault, but a guard secretly makes a copy and drops it in an unlocked recycling bin outside. We instruct the OS kernel to padlock the sensitive data inside the RAM vault.

**The Technical Implementation:**  
Volatile zeroing is useless if the kernel pages out memory. Intermediate buffers must be locked into physical RAM using POSIX `mlock`. Safely wrapping `libc::mlock` in Rust requires handling valid virtual addresses and gracefully falling back if `RLIMIT_MEMLOCK` (`ulimit -l`) is restricted:

```rust
/// Locks a byte slice in physical RAM via libc::mlock.
/// Returns true if pages were locked, or false on resource restrictions.
pub fn lock_memory(slice: &[u8]) -> bool {
    #[cfg(unix)]
    {
        if slice.is_empty() {
            return true;
        }
        // SAFETY: `slice.as_ptr()` points to an allocated, valid byte slice of length `slice.len()`.
        // `libc::mlock` reads the pointer and byte count to lock virtual memory pages into physical RAM.
        let res = unsafe { libc::mlock(slice.as_ptr() as *const libc::c_void, slice.len()) };
        res == 0
    }
    #[cfg(not(unix))]
    {
        let _ = slice;
        false
    }
}

/// Unlocks a previously locked byte slice via libc::munlock.
pub fn unlock_memory(slice: &[u8]) {
    #[cfg(unix)]
    {
        if !slice.is_empty() {
            // SAFETY: `slice.as_ptr()` points to a valid memory range of length `slice.len()`.
            unsafe { libc::munlock(slice.as_ptr() as *const libc::c_void, slice.len()); }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = slice;
    }
}
```

Notice that we avoid holding raw pointers or manual lifetimes: we lock and unlock borrowable byte slices directly on the pre-allocated ring-buffer slots.

---

### 3. SIMD-XOR: Auto-Vectorization vs. Hand-Written Intrinsics

**The Concept:**  
Obfuscating data by mixing it with random numbers byte-by-byte takes forever—like digging a trench with a teaspoon. We structure our data so the CPU can use its excavator bucket (processing huge 64-byte chunks in a single clock cycle), making the program process data as fast as the SSD can deliver it.

**The Technical Implementation:**  
For $N$-way secret combination ($P = C_1 \oplus \dots \oplus C_N$), CPU throughput must comfortably saturate the memory bus. Instead of relying on architecture-dependent assembly intrinsics (`avx2`, `neon`), we leverage LLVM's auto-vectorizer using an unrolled 64-byte word loop:

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

**Benchmark Results & Assembly Verification (x86_64, AVX2):**  
- Standard byte-by-byte iterator XOR: $\approx 1.1 \text{ GB/s}$
- 64-byte unrolled chunk XOR: **$\approx 4.02 \text{ GB/s}$**  
- **Verified Compiler Output:** Inspecting the emitted assembly (`cargo rustc --release -- --emit asm`) confirms that LLVM reliably auto-vectorizes this loop into 256-bit AVX2 instructions (`vpxor %ymm...` and `vinserti128`), avoiding scalar fallback.
- **Hardware Bottleneck:** At $\approx 4 \text{ GB/s}$, CPU execution latency drops below memory access latency; throughput fully saturates the memory controller and bus bandwidth on standard dual-channel x86_64 architectures. Completely Safe Rust without unsafe pointer offsets.

---

### 4. Parallel Disk Fanout & Cache Pressure (`fadvise`)

**The Concept:**  
Writing to a fast internal drive and a slow USB stick simultaneously usually causes the entire system to crawl at the speed of the slow USB stick. We introduced decoupled workers so the fast drive receives its data immediately while the USB writes at its own pace. Furthermore, we instruct the OS kernel to immediately clear its cache of written data so host memory doesn't get clogged with gigabytes of random noise.

**The Technical Implementation:**  
Spawning independent scoped worker threads (`std::thread::scope`) communicating over bounded channels allows each writer to operate at its storage medium's native speed. To prevent Terabytes of pseudorandom noise from thrashing the Linux Page Cache, we explicitly advise the kernel via `libc::posix_fadvise`:

- `POSIX_FADV_SEQUENTIAL`: Signals continuous readahead for the reader.
- `POSIX_FADV_DONTNEED`: Evicts written (dirty) pages directly out of the page cache immediately after the flush, preserving host RAM for active applications.

---

### Takeaways & Roadmap

- **Zero Allocations:** Pre-allocating bounded channel slots avoids runtime GC/allocator stalls entirely.
- **Defense in Depth:** The combination of `mlock`, `slice.zeroize()`, and `fadvise` guarantees strict volatile memory and cache hygiene.
- **Strictly Minimal Unsafe:** Out of $\approx 3{,}800$ lines of Rust code in the project, exactly 4 lines invoke `unsafe`—strictly bounded to POSIX kernel syscalls (`mlock`/`munlock` and `fadvise`), with full safety documentation. All SIMD and streaming logic is 100% Safe Rust.

I'm currently planning a lightweight native Desktop GUI (considering Slint or Iced) with Drag & Drop as the next milestone for non-terminal workflows.

If you are interested in looking at the full implementation or the concurrency tests, the source code is available here (LGPL v3):  
**https://github.com/Meik1982/random-filesplitter**

Have any of you tackled similar I/O bottlenecks when dealing with high-throughput streaming in Rust? I'd be particularly interested in hearing how others handle `mlock` limitations across different Unix environments.
