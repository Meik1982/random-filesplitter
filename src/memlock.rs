//! Cross-platform memory locking (`mlock` / `munlock`) to prevent paging
//! cryptographic key material and OTP buffers to disk swap partitions or hibernation files.

/// Locks a byte slice in physical RAM via `libc::mlock`.
///
/// Returns `true` if pages were successfully locked,
/// or `false` if OS policies or resource limits (`RLIMIT_MEMLOCK`) denied the request.
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

/// Unlocks a previously locked byte slice via `libc::munlock`.
#[allow(dead_code)]
pub fn unlock_memory(slice: &[u8]) {
    #[cfg(unix)]
    {
        if !slice.is_empty() {
            // SAFETY: `slice.as_ptr()` points to a valid memory range of length `slice.len()`.
            // Calling `libc::munlock` unlocks previously locked pages back to standard OS paging.
            unsafe {
                libc::munlock(slice.as_ptr() as *const libc::c_void, slice.len());
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = slice;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_and_unlock_memory() {
        let buf = vec![0x42u8; 4096];
        // Must never panic even when ulimit -l restricts mlock
        let _ = lock_memory(&buf);
        unlock_memory(&buf);
    }
}
