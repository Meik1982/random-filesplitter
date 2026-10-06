//! High-Performance Cryptography: ChaCha20 Stream Cipher & SIMD-XOR Operations.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Sichere Kapselung der ChaCha20-Streaming-Engine mit automatischer Nullung im Destruktor.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChaChaRng {
    #[zeroize(skip)]
    cipher: ChaCha20,
}

impl ChaChaRng {
    /// Initialisiert den ChaCha20 CSPRNG mit 256-Bit Schlüssel und 96-Bit Nonce.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let cipher = ChaCha20::new(key.into(), nonce.into());
        Self { cipher }
    }

    /// Füllt den übergebenen Puffer mit pseudozufälligem Schlüsselstrom.
    #[inline]
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        // In ChaCha20 ist die Keystream-Generierung äquivalent zum Verschlüsseln von Nullen.
        dest.fill(0);
        self.cipher.apply_keystream(dest);
    }

    /// Generiert ein einzelnes Pseudo-Zufallsbyte.
    #[inline]
    pub fn next_u8(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.cipher.apply_keystream(&mut b);
        b[0]
    }
}

/// Führt ein hochoptimiertes RAM-zu-RAM XOR zweier Puffer durch: `dest[i] ^= src[i]`.
/// Verwendet 32-Byte (256-Bit) Vektorschritte, die von LLVM/Rust automatisch in AVX2/NEON übersetzt werden,
/// mit 64-Bit und 8-Bit Fallback für Restbytes.
#[inline]
#[allow(dead_code)]
pub fn xor_in_place(dest: &mut [u8], src: &[u8]) {
    assert_eq!(
        dest.len(),
        src.len(),
        "Puffergrößen für XOR müssen exakt übereinstimmen"
    );

    let len = dest.len();
    let mut offset = 0;

    // 64-Byte / 512-Bit Super-Unrolled Vektor-Schleife (nutzt 2x AVX2 ymm-Register)
    while offset + 64 <= len {
        let d = &mut dest[offset..offset + 64];
        let s = &src[offset..offset + 64];

        for i in 0..64 {
            d[i] ^= s[i];
        }
        offset += 64;
    }

    // 8-Byte (64-Bit) Fast-Path
    while offset + 8 <= len {
        let d_val = u64::from_ne_bytes(dest[offset..offset + 8].try_into().unwrap());
        let s_val = u64::from_ne_bytes(src[offset..offset + 8].try_into().unwrap());
        dest[offset..offset + 8].copy_from_slice(&(d_val ^ s_val).to_ne_bytes());
        offset += 8;
    }

    // Restbytes (1 bis 7 Bytes)
    while offset < len {
        dest[offset] ^= src[offset];
        offset += 1;
    }
}

/// Führt ein 3-Wege XOR durch: `dest[i] = src1[i] ^ src2[i]`.
#[inline]
pub fn xor_buffers(dest: &mut [u8], src1: &[u8], src2: &[u8]) {
    assert_eq!(dest.len(), src1.len());
    assert_eq!(dest.len(), src2.len());

    let len = dest.len();
    let mut offset = 0;

    while offset + 64 <= len {
        let d = &mut dest[offset..offset + 64];
        let s1 = &src1[offset..offset + 64];
        let s2 = &src2[offset..offset + 64];

        for i in 0..64 {
            d[i] = s1[i] ^ s2[i];
        }
        offset += 64;
    }

    while offset + 8 <= len {
        let s1_val = u64::from_ne_bytes(src1[offset..offset + 8].try_into().unwrap());
        let s2_val = u64::from_ne_bytes(src2[offset..offset + 8].try_into().unwrap());
        dest[offset..offset + 8].copy_from_slice(&(s1_val ^ s2_val).to_ne_bytes());
        offset += 8;
    }

    while offset < len {
        dest[offset] = src1[offset] ^ src2[offset];
        offset += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_deterministic() {
        let key = [0x42u8; 32];
        let nonce = [0x13u8; 12];

        let mut rng1 = ChaChaRng::new(&key, &nonce);
        let mut rng2 = ChaChaRng::new(&key, &nonce);

        let mut buf1 = vec![0u8; 1024];
        let mut buf2 = vec![0u8; 1024];

        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
        assert_ne!(buf1, vec![0u8; 1024]);
    }

    #[test]
    fn test_simd_xor_correctness() {
        let mut dest = vec![0xAAu8; 127]; // Ungerade Länge zur Prüfung aller Ränder
        let src = vec![0x55u8; 127];

        xor_in_place(&mut dest, &src);

        // 0xAA ^ 0x55 == 0xFF
        assert_eq!(dest, vec![0xFFu8; 127]);

        // Nochmal xor mit src -> muss wieder 0xAA ergeben
        xor_in_place(&mut dest, &src);
        assert_eq!(dest, vec![0xAAu8; 127]);
    }

    #[test]
    fn test_xor_buffers_3way() {
        let s1 = vec![0xF0u8; 99];
        let s2 = vec![0x0Fu8; 99];
        let mut out = vec![0u8; 99];

        xor_buffers(&mut out, &s1, &s2);
        assert_eq!(out, vec![0xFFu8; 99]);
    }
}
