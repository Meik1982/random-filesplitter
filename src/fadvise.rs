//! High-Performance Direct I/O & OS Page Cache Advising (POSIX / Linux).
//! Enables sequential readahead and page cache bypass for multi-gigabyte files.

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Advises the OS kernel to enable aggressive sequential read-ahead.
#[cfg(unix)]
pub fn advise_sequential<F: AsRawFd>(file: &F) {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
    }
}

#[cfg(not(unix))]
pub fn advise_sequential<F>(_file: &F) {}

/// Advises the OS kernel to drop processed pages from the page cache.
#[cfg(unix)]
pub fn advise_drop_cache<F: AsRawFd>(file: &F, offset: i64, len: i64) {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), offset, len, libc::POSIX_FADV_DONTNEED);
    }
}

#[cfg(not(unix))]
pub fn advise_drop_cache<F>(_file: &F, _offset: i64, _len: i64) {}
