//! High-Performance Direct I/O & OS Page Cache Advising (POSIX / Linux).
//! Enables sequential readahead and page cache bypass for multi-gigabyte files.

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Advises the OS kernel to enable aggressive sequential read-ahead.
#[cfg(unix)]
pub fn advise_sequential<F: AsRawFd>(file: &F) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `file.as_raw_fd()` yields an active, open file descriptor owned by the caller.
        // `libc::posix_fadvise` with offset 0 and len 0 advises the kernel across the entire file.
        unsafe {
            libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        }
    }
}

#[cfg(not(unix))]
pub fn advise_sequential<F>(_file: &F) {}

/// Advises the OS kernel to drop processed pages from the page cache.
#[cfg(unix)]
pub fn advise_drop_cache<F: AsRawFd>(file: &F, offset: i64, len: i64) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `file.as_raw_fd()` is a valid, open file descriptor.
        // Passing `POSIX_FADV_DONTNEED` informs the OS that cached pages in [offset..offset+len] can be evicted.
        unsafe {
            libc::posix_fadvise(file.as_raw_fd(), offset, len, libc::POSIX_FADV_DONTNEED);
        }
    }
}

#[cfg(not(unix))]
pub fn advise_drop_cache<F>(_file: &F, _offset: i64, _len: i64) {}
