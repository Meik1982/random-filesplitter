//! Fuzzing & Malformed Input Robustness Test Suite for RFS.
//! Systematically evaluates `decode_footer_n_way`, metadata extractors, and parser bounds
//! against thousands of corrupted, truncated, bit-flipped, and pathological byte sequences.
//! Invariant: All parsers MUST return `Err` gracefully and NEVER panic, wrap around, or read out of bounds.

use rfs_core::crypto::ChaChaRng;
use rfs_core::format::{decode_footer_n_way, encode_rfs4_footer_n_way};
use rfs_core::types::{BLKS_DIGEST_SIZE, RFS4_MAGIC, RFS4_TRAILER_SIZE};

#[test]
fn test_fuzz_footer_arbitrary_random_inputs() {
    let mut rng_state: u64 = 0xDEADBEEFCAFEBABE;
    let mut xorshift64 = || {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        rng_state
    };

    // 10,000 iterations across varying lengths and part counts
    for _ in 0..10_000 {
        let len = (xorshift64() % 1024) as usize;
        let num_parts = ((xorshift64() % 7) + 1) as usize;

        let mut parts_storage: Vec<Vec<u8>> = Vec::with_capacity(num_parts);
        for _ in 0..num_parts {
            let mut buf = vec![0u8; len];
            for chunk in buf.chunks_mut(8) {
                let r = xorshift64().to_le_bytes();
                let copy_len = chunk.len().min(8);
                chunk[..copy_len].copy_from_slice(&r[..copy_len]);
            }
            parts_storage.push(buf);
        }

        let slice_refs: Vec<&[u8]> = parts_storage.iter().map(|v| v.as_slice()).collect();

        // Must never panic!
        let _ = decode_footer_n_way(&slice_refs);
    }
}

#[test]
fn test_fuzz_footer_bit_flip_mutations() {
    // Generate a known valid RFS4 footer
    let blks = [0x42u8; BLKS_DIGEST_SIZE];
    let original_size = 12345u64;
    let filename = "important_document.pdf";
    let mut rng = ChaChaRng::new(&[0x11u8; 32], &[0x22u8; 12]);
    let footers =
        encode_rfs4_footer_n_way(&blks, original_size, filename, 2, None, &mut rng).unwrap();

    let p1 = footers[0].clone();
    let p2 = footers[1].clone();

    let trailer_offset = p1.len() - RFS4_TRAILER_SIZE;

    // Single-bit flip sweep across every bit in the trailer
    for byte_idx in 0..p1.len() {
        for bit_idx in 0..8 {
            let mut corrupted_p1 = p1.clone();
            corrupted_p1[byte_idx] ^= 1 << bit_idx;

            let refs: [&[u8]; 2] = [&corrupted_p1, &p2];
            let res = decode_footer_n_way(&refs);

            // If magic tag was flipped (bytes trailer_offset..trailer_offset+4), it must strictly return Err
            if byte_idx >= trailer_offset && byte_idx < trailer_offset + 4 {
                assert!(
                    res.is_err(),
                    "Bit flip in magic tag (offset {}) must be rejected",
                    byte_idx
                );
            }
        }
    }
}

#[test]
fn test_fuzz_pathological_size_and_integer_overflows() {
    // Construct trailers with u64::MAX original sizes
    let mut pathological = vec![0u8; RFS4_TRAILER_SIZE];
    pathological[0..4].copy_from_slice(&RFS4_MAGIC);
    pathological[4..6].copy_from_slice(&[0x04, 0x00]);
    pathological[6..14].copy_from_slice(&u64::MAX.to_le_bytes()); // Maximum size
    pathological[62..64].copy_from_slice(&10u16.to_le_bytes()); // 10 byte filename

    // Append 10 bytes of filename
    let mut full = vec![0x78u8; 10];
    full.extend_from_slice(&pathological);
    let zero_share = vec![0u8; full.len()];

    let refs: [&[u8]; 2] = [&full, &zero_share];
    let res = decode_footer_n_way(&refs);

    // Parsing succeeds, and inspect original_size
    let meta = res.expect("Valid 2-share trailer with u64::MAX size should parse metadata");
    assert_eq!(meta.original_size(), u64::MAX);

    // Now test with filename length u16::MAX but payload slice smaller (64 bytes)
    pathological[62..64].copy_from_slice(&u16::MAX.to_le_bytes());
    let zero_64 = vec![0u8; RFS4_TRAILER_SIZE];
    let refs_truncated: [&[u8]; 2] = [&pathological, &zero_64];
    let res_truncated = decode_footer_n_way(&refs_truncated);
    assert!(
        res_truncated.is_err(),
        "Trailer declaring u16::MAX filename length on 64-byte slice must return Err"
    );
}

#[test]
fn test_fuzz_empty_and_sub_minimum_slices() {
    for len in 0..RFS4_TRAILER_SIZE {
        let dummy = vec![0xFFu8; len];
        let refs: [&[u8]; 1] = [&dummy];
        assert!(decode_footer_n_way(&refs).is_err());
    }
}
