//! Plattformübergreifendes Memory-Locking (`mlock` / `munlock`) zur Verhinderung
//! von Auslagerungen kryptografischer Daten und OTP-Puffer in Swap-Dateien.

/// Sperrt einen Byte-Puffer im physischen RAM via `libc::mlock`.
///
/// Liefert `true`, wenn die Seiten erfolgreich gesperrt wurden,
/// oder `false`, falls das Betriebssystem oder Ressourcenlimits (`RLIMIT_MEMLOCK`)
/// dies verweigern.
pub fn lock_memory(slice: &[u8]) -> bool {
    #[cfg(unix)]
    {
        if slice.is_empty() {
            return true;
        }
        let res = unsafe { libc::mlock(slice.as_ptr() as *const libc::c_void, slice.len()) };
        res == 0
    }
    #[cfg(not(unix))]
    {
        let _ = slice;
        false
    }
}

/// Hebt die physische RAM-Sperrung für einen Byte-Puffer via `libc::munlock` auf.
#[allow(dead_code)]
pub fn unlock_memory(slice: &[u8]) {
    #[cfg(unix)]
    {
        if !slice.is_empty() {
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
        // Test darf niemals panicken, selbst wenn ulimit -l mlock einschränkt
        let _ = lock_memory(&buf);
        unlock_memory(&buf);
    }
}
