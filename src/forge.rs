//! Deniable Decoy Forge Engine (`rfs forge` / Rubber-Hose Resilience).
//! Synthesizes a mathematically tailor-made counterfeit share $C_{fake}$ from $K$ seized shares
//! such that $C_1 \oplus \dots \oplus C_K \oplus C_{fake}$ decrypts bit-exact to a harmless decoy plaintext
//! with 100% cryptographic integrity (BLKS-384 / RFS4 Stealth Trailer).

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto::ChaChaRng;
use crate::entropy::UniversalEntropyHarvester;
use crate::telemetry::format_bytes;
use crate::types::{RFS4_MAGIC, RFS4_TRAILER_SIZE};
use blks_core::BlksHasher;

/// Synthesizes a fake share file $C_{fake}$ matching existing shares and revealing a benign decoy plaintext.
pub fn forge_decoy_share(
    existing_shares: &[PathBuf],
    decoy_plaintext_path: &Path,
    output_fake_share: &Path,
    block_size: usize,
    direct_io: bool,
    force: bool,
) -> Result<(), String> {
    if existing_shares.is_empty() {
        return Err("At least 1 existing share file required to forge a counterpart.".to_string());
    }

    if !decoy_plaintext_path.exists() {
        return Err(format!(
            "Decoy plaintext file '{}' does not exist.",
            decoy_plaintext_path.display()
        ));
    }

    // Check destination collisions
    for (idx, p) in existing_shares.iter().enumerate() {
        if output_fake_share == p {
            return Err(format!(
                "Output file '{}' must not collide with existing source share {}.",
                output_fake_share.display(),
                idx + 1
            ));
        }
    }

    if output_fake_share.exists() && !force {
        return Err(format!(
            "Output file '{}' already exists. Use --force to overwrite.",
            output_fake_share.display()
        ));
    }

    // 1. Verify that all existing shares exist and have identical byte lengths
    let mut share_size: Option<u64> = None;
    for p in existing_shares {
        let meta = fs::metadata(p)
            .map_err(|e| format!("Cannot inspect metadata of share '{}': {}", p.display(), e))?;
        if let Some(s) = share_size {
            if meta.len() != s {
                return Err(format!(
                    "Share size mismatch: '{}' is {} bytes, but prior share is {} bytes. All RFS4 shares must be identical.",
                    p.display(),
                    meta.len(),
                    s
                ));
            }
        } else {
            share_size = Some(meta.len());
        }
    }

    let target_share_size = share_size.unwrap_or(0);
    if target_share_size < RFS4_TRAILER_SIZE as u64 {
        return Err("Existing shares are too small to contain a valid RFS4 footer.".to_string());
    }

    // 2. Inspect decoy plaintext metadata
    let decoy_meta = fs::metadata(decoy_plaintext_path).map_err(|e| {
        format!(
            "Cannot inspect metadata of decoy file '{}': {}",
            decoy_plaintext_path.display(),
            e
        )
    })?;
    let decoy_size = decoy_meta.len();

    let decoy_filename = decoy_plaintext_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("decoy.bin");
    let fn_bytes = decoy_filename.as_bytes();
    let fn_len = fn_bytes.len();

    if fn_len > u16::MAX as usize {
        return Err("Decoy filename is too long (maximum 65535 bytes).".to_string());
    }

    let min_required_size = decoy_size
        .checked_add(fn_len as u64)
        .and_then(|s| s.checked_add(RFS4_TRAILER_SIZE as u64))
        .ok_or_else(|| "Size overflow during calculation".to_string())?;

    if min_required_size > target_share_size {
        return Err(format!(
            "Decoy plaintext is too large: requires {} bytes, but existing shares are only {} bytes. Decoy must be smaller or equal to target share size.",
            format_bytes(min_required_size),
            format_bytes(target_share_size)
        ));
    }

    let pad_len = target_share_size - min_required_size;

    // 3. Compute BLKS-384 hash of the decoy plaintext
    let mut blks_hasher = BlksHasher::new();
    let mut decoy_reader = BufReader::with_capacity(
        block_size,
        File::open(decoy_plaintext_path).map_err(|e| {
            format!(
                "Cannot open decoy file '{}': {}",
                decoy_plaintext_path.display(),
                e
            )
        })?,
    );

    let mut hash_buf = vec![0u8; block_size];
    let mut rem_hash = decoy_size;
    while rem_hash > 0 {
        let to_read = (rem_hash as usize).min(block_size);
        decoy_reader
            .read_exact(&mut hash_buf[..to_read])
            .map_err(|e| format!("Read error calculating hash of decoy file: {}", e))?;
        blks_hasher.update(&hash_buf[..to_read]);
        rem_hash -= to_read as u64;
    }
    hash_buf.as_mut_slice().zeroize();
    let decoy_blks_digest = blks_hasher.finalize();

    // 4. Open existing shares for streaming XOR
    let mut share_readers: Vec<BufReader<File>> = Vec::with_capacity(existing_shares.len());
    for p in existing_shares {
        let f = File::open(p)
            .map_err(|e| format!("Cannot open existing share '{}': {}", p.display(), e))?;
        if direct_io {
            crate::fadvise::advise_sequential(&f);
        }
        share_readers.push(BufReader::with_capacity(block_size, f));
    }

    // 5. Open output fake share
    let fake_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_fake_share)
        .map_err(|e| {
            format!(
                "Cannot create forged share file '{}': {}",
                output_fake_share.display(),
                e
            )
        })?;

    if direct_io {
        crate::fadvise::advise_sequential(&fake_file);
    }
    let mut fake_writer = BufWriter::with_capacity(block_size, fake_file);

    // Reset decoy reader to start of file for streaming XOR
    decoy_reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| format!("Seek error on decoy file: {}", e))?;

    let mut buf_decoy = vec![0u8; block_size];
    let mut buf_share = vec![0u8; block_size];

    // --- PHASE 1: Payload Stream XOR ---
    // C_fake[i] = C_1[i] ^ ... ^ C_K[i] ^ P_decoy[i]
    let mut rem_payload = decoy_size;
    while rem_payload > 0 {
        let to_process = (rem_payload as usize).min(block_size);
        decoy_reader
            .read_exact(&mut buf_decoy[..to_process])
            .map_err(|e| format!("Read error streaming decoy file: {}", e))?;

        for sr in &mut share_readers {
            sr.read_exact(&mut buf_share[..to_process])
                .map_err(|e| format!("Read error on existing share: {}", e))?;
            for i in 0..to_process {
                buf_decoy[i] ^= buf_share[i];
            }
        }

        fake_writer
            .write_all(&buf_decoy[..to_process])
            .map_err(|e| format!("Write error on forged share: {}", e))?;

        rem_payload -= to_process as u64;
    }

    // --- PHASE 2: Padding Stream XOR ---
    // C_fake[p] = C_1[p] ^ ... ^ C_K[p] ^ ChaCha20_Noise[p]
    if pad_len > 0 {
        let (mut key, mut nonce) = UniversalEntropyHarvester::harvest_seed();
        let mut rng = ChaChaRng::new(&key, &nonce);
        key.zeroize();
        nonce.zeroize();

        let mut rem_pad = pad_len;
        while rem_pad > 0 {
            let to_process = (rem_pad as usize).min(block_size);
            rng.fill_bytes(&mut buf_decoy[..to_process]);

            for sr in &mut share_readers {
                sr.read_exact(&mut buf_share[..to_process])
                    .map_err(|e| format!("Read error on existing share during padding: {}", e))?;
                for i in 0..to_process {
                    buf_decoy[i] ^= buf_share[i];
                }
            }

            fake_writer
                .write_all(&buf_decoy[..to_process])
                .map_err(|e| format!("Write error on forged share during padding: {}", e))?;

            rem_pad -= to_process as u64;
        }
    }

    // --- PHASE 3: Embedded Filename XOR ---
    // C_fake[fn] = C_1[fn] ^ ... ^ C_K[fn] ^ Filename[fn]
    let mut buf_fn = fn_bytes.to_vec();
    let mut buf_fn_share = vec![0u8; fn_len];
    for sr in &mut share_readers {
        sr.read_exact(&mut buf_fn_share)
            .map_err(|e| format!("Read error reading filename slice from share: {}", e))?;
        for i in 0..fn_len {
            buf_fn[i] ^= buf_fn_share[i];
        }
    }
    fake_writer
        .write_all(&buf_fn)
        .map_err(|e| format!("Write error writing forged filename slice: {}", e))?;

    // --- PHASE 4: Stealth RFS4 Trailer XOR (64 Bytes) ---
    // [0..4] Magic ("RFS4")
    // [4..6] Version (0x04, 0x00)
    // [6..14] Original size (u64 LE, 8 Bytes)
    // [14..62] BLKS-384 Hash (48 Bytes)
    // [62..64] Filename length (u16 LE, 2 Bytes)
    let mut plain_trailer = [0u8; RFS4_TRAILER_SIZE];
    plain_trailer[0..4].copy_from_slice(&RFS4_MAGIC);
    plain_trailer[4..6].copy_from_slice(&[0x04, 0x00]);
    plain_trailer[6..14].copy_from_slice(&decoy_size.to_le_bytes());
    plain_trailer[14..62].copy_from_slice(&decoy_blks_digest);
    plain_trailer[62..64].copy_from_slice(&(fn_len as u16).to_le_bytes());

    let mut trailer_share = [0u8; RFS4_TRAILER_SIZE];
    for sr in &mut share_readers {
        sr.read_exact(&mut trailer_share)
            .map_err(|e| format!("Read error reading 64-byte trailer from share: {}", e))?;
        for i in 0..RFS4_TRAILER_SIZE {
            plain_trailer[i] ^= trailer_share[i];
        }
    }

    fake_writer
        .write_all(&plain_trailer)
        .map_err(|e| format!("Write error writing forged 64-byte trailer: {}", e))?;

    fake_writer
        .flush()
        .map_err(|e| format!("Flush error on forged share: {}", e))?;

    // Clean up sensitive memory
    buf_decoy.as_mut_slice().zeroize();
    buf_share.as_mut_slice().zeroize();
    buf_fn.as_mut_slice().zeroize();
    buf_fn_share.as_mut_slice().zeroize();
    plain_trailer.zeroize();
    trailer_share.zeroize();

    Ok(())
}
