//! Bounded HPACK decoding for guest HTTP/2 request header blocks.
//!
//! Header blocks come from the guest, so malformed input must be an error,
//! never a panic. `loona-hpack` reports malformed input as errors. It builds a
//! Huffman table for every Huffman-coded string and cannot stop early, so a
//! structural pre-scan enforces the field limit before any string is decoded.

use loona_hpack::Decoder;
use loona_hpack::decoder::DecoderError;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Largest HPACK dynamic table a guest may select with a table size update
/// (the RFC 9113 default `SETTINGS_HEADER_TABLE_SIZE`).
const MAX_DYNAMIC_TABLE_BYTES: usize = 4096;

/// Continuation octets allowed in one HPACK integer. This matches the
/// `loona-hpack` limit (RFC 7541 §5.1 allows rejecting excessively long
/// integers) and keeps every value below 2^29.
const MAX_INTEGER_CONTINUATION_OCTETS: usize = 4;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Limits applied to one decoded header list.
#[derive(Debug, Clone, Copy)]
pub(super) struct HeaderListLimits {
    /// Maximum number of fields in one header block.
    pub(super) max_fields: usize,
    /// Maximum decoded size, counting each field as `name + value + 4` bytes.
    pub(super) max_decoded_bytes: usize,
}

/// Decoded `(name, value)` fields in block order.
pub(super) type HeaderList = Vec<(Vec<u8>, Vec<u8>)>;

/// Why a guest header block was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum HeaderBlockError {
    /// The block is not valid HPACK.
    #[error("malformed HPACK header block")]
    Malformed,
    /// The block has more fields than [`HeaderListLimits::max_fields`].
    #[error("header block exceeds the field limit")]
    TooManyFields,
    /// The decoded fields exceed [`HeaderListLimits::max_decoded_bytes`].
    #[error("decoded header list exceeds the size limit")]
    TooLarge,
}

/// Connection-scoped HPACK decoder for guest request header blocks.
///
/// The dynamic table carries over between blocks, so the connection must be
/// closed after any error.
pub(super) struct HeaderBlockDecoder {
    decoder: Decoder<'static>,
    limits: HeaderListLimits,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HeaderBlockDecoder {
    /// Create a decoder with an empty dynamic table.
    pub(super) fn new(limits: HeaderListLimits) -> Self {
        let mut decoder = Decoder::new();
        decoder.set_max_allowed_table_size(MAX_DYNAMIC_TABLE_BYTES);
        Self { decoder, limits }
    }

    /// Decode one complete header block (the HEADERS fragment followed by
    /// every CONTINUATION payload) into `(name, value)` pairs in block order.
    pub(super) fn decode(&mut self, block: &[u8]) -> Result<HeaderList, HeaderBlockError> {
        let fields = count_fields(block).ok_or(HeaderBlockError::Malformed)?;
        if fields > self.limits.max_fields {
            return Err(HeaderBlockError::TooManyFields);
        }

        let mut headers = Vec::with_capacity(fields);
        let mut decoded_bytes = 0usize;
        let mut too_large = false;
        // The callback cannot stop the decoder. Once the size limit is hit,
        // skip the remaining fields and reject the block afterwards.
        let result = self.decoder.decode_with_cb(block, |name, value| {
            if too_large {
                return;
            }
            decoded_bytes = decoded_bytes
                .saturating_add(name.len())
                .saturating_add(value.len())
                .saturating_add(4);
            if decoded_bytes > self.limits.max_decoded_bytes {
                too_large = true;
                return;
            }
            headers.push((name.into_owned(), value.into_owned()));
        });
        match result {
            Ok(()) => {}
            // `loona-hpack` rejects any block that ends with a table size
            // update. A block made only of updates is valid (RFC 7541 §4.2),
            // for example an empty trailer after a table size change, and
            // the decoder has already applied every update when it reports
            // this.
            Err(DecoderError::SizeUpdateAtEnd) if fields == 0 => {}
            Err(_) => return Err(HeaderBlockError::Malformed),
        }

        if too_large {
            return Err(HeaderBlockError::TooLarge);
        }
        Ok(headers)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Count the header fields in `block` without decoding strings or touching
/// a dynamic table (RFC 7541 §6). Returns `None` if a representation is
/// truncated or an integer is too long. Index validity is left to the decoder.
fn count_fields(block: &[u8]) -> Option<usize> {
    let mut pos = 0;
    let mut fields = 0;
    while let Some(&first) = block.get(pos) {
        if first & 0x80 != 0 {
            // Indexed field (§6.1).
            pos += read_integer(&block[pos..], 7)?.1;
            fields += 1;
        } else if first & 0xe0 == 0x20 {
            // Dynamic table size update (§6.3).
            pos += read_integer(&block[pos..], 5)?.1;
        } else {
            // Literal field (§6.2): with incremental indexing uses a 6-bit
            // name index, without or never indexed a 4-bit one.
            let prefix_bits = if first & 0x40 != 0 { 6 } else { 4 };
            let (name_index, len) = read_integer(&block[pos..], prefix_bits)?;
            pos += len;
            if name_index == 0 {
                pos = skip_string(block, pos)?;
            }
            pos = skip_string(block, pos)?;
            fields += 1;
        }
    }
    Some(fields)
}

/// Decode an HPACK integer with a `prefix_bits`-bit prefix (§5.1). Returns
/// the value and the number of octets used.
fn read_integer(buf: &[u8], prefix_bits: u32) -> Option<(usize, usize)> {
    let mask = (1usize << prefix_bits) - 1;
    let mut value = usize::from(*buf.first()?) & mask;
    if value < mask {
        return Some((value, 1));
    }
    let continuation = buf.get(1..)?.iter().take(MAX_INTEGER_CONTINUATION_OCTETS);
    for (i, &octet) in continuation.enumerate() {
        value += usize::from(octet & 0x7f) << (7 * i);
        if octet & 0x80 == 0 {
            return Some((value, i + 2));
        }
    }
    None
}

/// Skip the string literal at `pos` (§5.2) and return the offset after it.
fn skip_string(block: &[u8], pos: usize) -> Option<usize> {
    let (len, used) = read_integer(block.get(pos..)?, 7)?;
    let end = pos + used + len;
    (end <= block.len()).then_some(end)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
pub(super) mod tests {
    use httlib_hpack::{Decoder as HttlibDecoder, Encoder};

    use super::*;

    const LIMITS: HeaderListLimits = HeaderListLimits {
        max_fields: 1024,
        max_decoded_bytes: 64 * 1024,
    };

    /// Blocks that made httlib-hpack 0.1.3 index out of bounds.
    pub(crate) const PANICKING_BLOCKS: [&[u8]; 4] =
        [&[0xff], &[0x67], &[0x7f, 0xc5], &[0x34, 0x22, 0x42]];

    /// Valid Huffman-coded strings from RFC 7541 Appendix C.4.
    const HUFFMAN_STRINGS: [&[u8]; 4] = [
        &[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ],
        &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf],
        &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
        &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
    ];

    /// Deterministic xorshift64 generator, so failures reproduce from the
    /// printed block without a seed file.
    pub(crate) struct Rng(pub(crate) u64);

    impl Rng {
        pub(crate) fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        pub(crate) fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn byte(&mut self) -> u8 {
            self.next() as u8
        }
    }

    /// A random header block: up to five HPACK representations (indexed,
    /// size update, literal with a raw, Huffman or random-Huffman string),
    /// then sometimes truncated, corrupted or extended with random bytes.
    /// About half of the blocks are valid (49% on the seed used below), so
    /// decoding reaches the dynamic table and Huffman paths instead of
    /// failing on the first octet.
    pub(crate) fn random_block(rng: &mut Rng) -> Vec<u8> {
        let mut block = Vec::new();
        for i in 0..rng.below(6) {
            match rng.below(8) {
                0 if i == 0 => {
                    let size = [0, 64, 4096, 4097, rng.below(5000)][rng.below(5)];
                    push_integer(&mut block, 0x20, 5, size);
                }
                0..=2 => push_integer(&mut block, 0x80, 7, random_index(rng)),
                _ => {
                    // Incremental indexing, without indexing, never indexed.
                    let (pattern, prefix_bits) = [(0x40, 6), (0x00, 4), (0x10, 4)][rng.below(3)];
                    let name_index = [0, 0, random_index(rng)][rng.below(3)];
                    push_integer(&mut block, pattern, prefix_bits, name_index);
                    if name_index == 0 {
                        push_string(&mut block, rng);
                    }
                    push_string(&mut block, rng);
                }
            }
        }
        match rng.below(8) {
            0 => block.truncate(rng.below(block.len() + 1)),
            1 if !block.is_empty() => {
                let at = rng.below(block.len());
                block[at] = rng.byte();
            }
            2 => block.extend((0..1 + rng.below(4)).map(|_| rng.byte())),
            _ => {}
        }
        block
    }

    /// Mostly static-table indices, some early dynamic-table indices, and
    /// occasionally anything up to 127 (including the invalid 0).
    fn random_index(rng: &mut Rng) -> usize {
        match rng.below(16) {
            0 => rng.below(128),
            1..=3 => 62 + rng.below(4),
            _ => 1 + rng.below(61),
        }
    }

    /// Append an RFC 7541 §5.1 integer.
    fn push_integer(block: &mut Vec<u8>, pattern: u8, prefix_bits: u32, value: usize) {
        let mask = (1usize << prefix_bits) - 1;
        if value < mask {
            block.push(pattern | value as u8);
            return;
        }
        block.push(pattern | mask as u8);
        let mut rest = value - mask;
        while rest >= 0x80 {
            block.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        block.push(rest as u8);
    }

    /// Append an RFC 7541 §5.2 string literal.
    fn push_string(block: &mut Vec<u8>, rng: &mut Rng) {
        match rng.below(10) {
            0..=5 => {
                let len = rng.below(12);
                push_integer(block, 0x00, 7, len);
                block.extend((0..len).map(|_| b'a' + rng.below(26) as u8));
            }
            6..=8 => {
                let huffman = HUFFMAN_STRINGS[rng.below(HUFFMAN_STRINGS.len())];
                push_integer(block, 0x80, 7, huffman.len());
                block.extend_from_slice(huffman);
            }
            _ => {
                // Random Huffman data: exercises padding and EOS checks.
                let len = rng.below(6);
                push_integer(block, 0x80, 7, len);
                block.extend((0..len).map(|_| rng.byte()));
            }
        }
    }

    fn reference_decoder() -> Decoder<'static> {
        let mut decoder = Decoder::new();
        decoder.set_max_allowed_table_size(MAX_DYNAMIC_TABLE_BYTES);
        decoder
    }

    /// Plain `loona-hpack` decoding, except that a block made only of table
    /// size updates is accepted, which `HeaderBlockDecoder` does on purpose.
    /// This checks the wrapper against the library; it is not an RFC oracle.
    fn reference_decode(reference: &mut Decoder<'static>, block: &[u8]) -> Option<HeaderList> {
        let mut fields = Vec::new();
        let result = reference.decode_with_cb(block, |name, value| {
            fields.push((name.into_owned(), value.into_owned()));
        });
        match result {
            Ok(()) => Some(fields),
            Err(DecoderError::SizeUpdateAtEnd) if fields.is_empty() => Some(fields),
            Err(_) => None,
        }
    }

    #[test]
    fn malformed_blocks_are_errors() {
        let others: [&[u8]; 5] = [
            // Size update with its integer cut off.
            &[0x3f],
            // Literal name "a" declared 5 bytes long.
            &[0x00, 0x05, 0x61],
            // Huffman string of one 0xff byte: padding longer than 7 bits.
            &[0x00, 0x81, 0xff, 0x80],
            // Index 0 is never valid.
            &[0x80],
            // Never-indexed literal with an empty value whose 5-byte Huffman
            // name ends in non-EOS padding bits (RFC 7541 §5.2). The valid
            // form ends in `bf`; see the positive test below.
            &[0x10, 0x85, 0xf5, 0xb2, 0x01, 0x01, 0xb3, 0x00],
        ];
        for block in PANICKING_BLOCKS.into_iter().chain(others) {
            let mut decoder = HeaderBlockDecoder::new(LIMITS);
            assert_eq!(
                decoder.decode(block),
                Err(HeaderBlockError::Malformed),
                "{block:02x?}"
            );
        }
    }

    #[test]
    fn non_eos_huffman_padding_is_rejected_and_eos_padding_is_accepted() {
        // The same never-indexed literal and Huffman name, with only the last
        // Huffman octet changed: `b3` pads with non-EOS bits and is rejected
        // (RFC 7541 §5.2), while `bf` pads with EOS bits and is accepted.
        // `httlib-hpack` 0.1.3 accepted the `b3` form, so pinning it here
        // documents the one guest-visible decoding change (plan §8.2).
        let rejected: &[u8] = &[0x10, 0x85, 0xf5, 0xb2, 0x01, 0x01, 0xb3, 0x00];
        let accepted: &[u8] = &[0x10, 0x85, 0xf5, 0xb2, 0x01, 0x01, 0xbf, 0x00];

        assert_eq!(
            HeaderBlockDecoder::new(LIMITS).decode(rejected),
            Err(HeaderBlockError::Malformed)
        );
        let fields = HeaderBlockDecoder::new(LIMITS).decode(accepted).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].1, b"");
    }

    #[test]
    fn random_blocks_never_panic_and_match_the_reference_decoder() {
        // Each connection feeds up to four blocks through one decoder, so
        // dynamic-table entries from earlier blocks are referenced later.
        let mut rng = Rng(0x243f_6a88_85a3_08d3);
        for _ in 0..2_000 {
            let mut decoder = HeaderBlockDecoder::new(LIMITS);
            let mut reference = reference_decoder();
            for _ in 0..4 {
                let block = random_block(&mut rng);
                let expected = reference_decode(&mut reference, &block);
                if let Some(fields) = &expected {
                    assert_eq!(count_fields(&block), Some(fields.len()), "{block:02x?}");
                }
                let actual = decoder.decode(&block);
                assert_eq!(actual.as_ref().ok(), expected.as_ref(), "{block:02x?}");
                if actual.is_err() {
                    // The handler closes the connection after any error.
                    break;
                }
            }
        }
    }

    #[test]
    fn uniform_random_bytes_never_panic() {
        // Unstructured input, next to the grammar-based generator above:
        // uniformly random bytes at every length from 0 to 32.
        let mut rng = Rng(0xa409_3822_299f_31d0);
        for _ in 0..500 {
            let mut decoder = HeaderBlockDecoder::new(LIMITS);
            let mut reference = reference_decoder();
            for len in 0..=32 {
                let block: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
                let expected = reference_decode(&mut reference, &block);
                let actual = decoder.decode(&block);
                assert_eq!(actual.as_ref().ok(), expected.as_ref(), "{block:02x?}");
                if actual.is_err() {
                    // Start a fresh connection, as the handler would.
                    decoder = HeaderBlockDecoder::new(LIMITS);
                    reference = reference_decoder();
                }
            }
        }
    }

    #[test]
    fn integer_boundaries_are_handled_for_every_prefix() {
        // Indexed (7-bit), literal with incremental indexing (6-bit), without
        // indexing and never indexed (4-bit), and table size update (5-bit).
        for (pattern, prefix_bits) in [(0x80, 7), (0x40, 6), (0x00, 4), (0x10, 4), (0x20, 5)] {
            let mask = (1u8 << prefix_bits) - 1;
            let max = usize::from(mask);
            let full = pattern | mask;
            let integers: [(&[u8], Option<usize>); 8] = [
                // Largest value that fits in the prefix.
                (&[pattern | (mask - 1)], Some(max - 1)),
                // Smallest value that needs a continuation octet.
                (&[full, 0x00], Some(max)),
                // Largest value with four continuation octets: 2^28 - 1 more.
                (&[full, 0xff, 0xff, 0xff, 0x7f], Some(max + (1 << 28) - 1)),
                // A fifth continuation octet is too long.
                (&[full, 0x80, 0x80, 0x80, 0x80, 0x00], None),
                // Truncated after each octet.
                (&[full], None),
                (&[full, 0x80], None),
                (&[full, 0x80, 0x80, 0x80], None),
                (&[full, 0x80, 0x80, 0x80, 0x80], None),
            ];
            for (integer, value) in integers {
                assert_eq!(
                    read_integer(integer, prefix_bits).map(|(value, _)| value),
                    value,
                    "{integer:02x?}"
                );
                // As a whole block: literals get the value `b`.
                let mut block = integer.to_vec();
                if pattern & 0xa0 == 0 {
                    block.extend_from_slice(&[0x01, b'b']);
                }
                let actual = HeaderBlockDecoder::new(LIMITS).decode(&block);
                let expected = reference_decode(&mut reference_decoder(), &block);
                assert_eq!(actual.as_ref().ok(), expected.as_ref(), "{block:02x?}");
                if value.is_none() {
                    assert_eq!(actual, Err(HeaderBlockError::Malformed), "{block:02x?}");
                }
            }
        }
        // String lengths (7-bit prefix, raw and Huffman): a maximum-width
        // length runs past the end, and a fifth continuation octet is rejected.
        for huffman in [0x00, 0x80] {
            for length in [
                [huffman | 0x7f, 0xff, 0xff, 0xff, 0x7f, b'a'],
                [huffman | 0x7f, 0x80, 0x80, 0x80, 0x80, 0x00],
            ] {
                let mut block = vec![0x00];
                block.extend_from_slice(&length);
                assert_eq!(count_fields(&block), None, "{block:02x?}");
                assert_eq!(
                    HeaderBlockDecoder::new(LIMITS).decode(&block),
                    Err(HeaderBlockError::Malformed),
                    "{block:02x?}"
                );
            }
        }
    }

    #[test]
    fn integers_with_padding_octets_are_accepted() {
        // Size update 31 with four continuation octets (`80 80 80 00`) is a
        // valid, non-minimal encoding. Five continuation octets are rejected.
        let mut decoder = HeaderBlockDecoder::new(LIMITS);
        assert_eq!(
            decoder.decode(&[0x3f, 0x80, 0x80, 0x80, 0x00, 0x82]),
            Ok(vec![(b":method".to_vec(), b"GET".to_vec())])
        );
        let mut decoder = HeaderBlockDecoder::new(LIMITS);
        assert_eq!(
            decoder.decode(&[0x3f, 0x80, 0x80, 0x80, 0x80, 0x00, 0x82]),
            Err(HeaderBlockError::Malformed)
        );
    }

    #[test]
    fn dynamic_table_state_carries_across_blocks() {
        let mut rng = Rng(0x1319_8a2e_0370_7344);
        let mut encoder = Encoder::with_dynamic_size(4096);
        let mut decoder = HeaderBlockDecoder::new(LIMITS);
        for round in 0..200 {
            let mut block = Vec::new();
            if round % 50 == 49 {
                // Shrink, then restore the table: evicts every entry.
                encoder.update_max_dynamic_size(0, &mut block).unwrap();
                encoder.update_max_dynamic_size(4096, &mut block).unwrap();
            }
            let mut expected = Vec::new();
            for _ in 0..1 + rng.below(8) {
                let name = format!("x-h{}", rng.below(6)).into_bytes();
                // Values up to 300 bytes force evictions from a 4 KiB table.
                let value = vec![b'a' + rng.below(4) as u8; rng.below(300)];
                let flags = [
                    Encoder::BEST_FORMAT | Encoder::WITH_INDEXING,
                    Encoder::WITH_INDEXING | Encoder::HUFFMAN_NAME | Encoder::HUFFMAN_VALUE,
                    Encoder::NEVER_INDEXED,
                    Encoder::BEST_FORMAT,
                    0,
                ][rng.below(5)];
                encoder
                    .encode((name.clone(), value.clone(), flags), &mut block)
                    .unwrap();
                expected.push((name, value));
            }
            assert_eq!(decoder.decode(&block).unwrap(), expected, "round {round}");
        }
    }

    #[test]
    fn table_size_update_above_limit_is_rejected() {
        // `3f e1 1f` = size update to 4096, `3f e2 1f` = 4097. `82` = :method GET.
        let mut decoder = HeaderBlockDecoder::new(LIMITS);
        assert_eq!(
            decoder.decode(&[0x3f, 0xe1, 0x1f, 0x82]).unwrap(),
            vec![(b":method".to_vec(), b"GET".to_vec())]
        );
        let mut decoder = HeaderBlockDecoder::new(LIMITS);
        assert_eq!(
            decoder.decode(&[0x3f, 0xe2, 0x1f, 0x82]),
            Err(HeaderBlockError::Malformed)
        );
    }

    #[test]
    fn size_update_only_blocks_are_accepted_and_applied() {
        // `40 01 61 01 62` adds `a: b` to the dynamic table; `be` is index 62.
        // `20` is a size update to 0, `3f e1 1f` one to 4096.
        let insert = [0x40, 0x01, b'a', 0x01, b'b'];
        let entry = vec![(b"a".to_vec(), b"b".to_vec())];
        let mut decoder = HeaderBlockDecoder::new(LIMITS);
        assert_eq!(decoder.decode(&insert), Ok(entry.clone()));
        // An empty block and an update that keeps the size keep the entry.
        assert_eq!(decoder.decode(&[]), Ok(Vec::new()));
        assert_eq!(decoder.decode(&[0x3f, 0xe1, 0x1f]), Ok(Vec::new()));
        assert_eq!(decoder.decode(&[0xbe]), Ok(entry.clone()));
        // Shrinking to 0 and growing back evicts it.
        assert_eq!(decoder.decode(&[0x20, 0x3f, 0xe1, 0x1f]), Ok(Vec::new()));
        assert_eq!(decoder.decode(&insert), Ok(entry.clone()));
        assert_eq!(decoder.decode(&[0xbe]), Ok(entry.clone()));
        // A lone `20` evicts it too.
        assert_eq!(decoder.decode(&[0x20]), Ok(Vec::new()));
        assert_eq!(decoder.decode(&[0xbe]), Err(HeaderBlockError::Malformed));

        // httlib-hpack, the previous decoder, also accepted these blocks.
        for block in [&[0x20][..], &[0x3f, 0xe1, 0x1f], &[0x20, 0x3f, 0xe1, 0x1f]] {
            let mut fields = Vec::new();
            HttlibDecoder::with_dynamic_size(4096)
                .decode(&mut block.to_vec(), &mut fields)
                .unwrap();
            assert!(fields.is_empty());
            assert_eq!(
                HeaderBlockDecoder::new(LIMITS).decode(block),
                Ok(Vec::new())
            );
        }

        // The table size cap applies to update-only blocks as well.
        assert_eq!(
            HeaderBlockDecoder::new(LIMITS).decode(&[0x3f, 0xe2, 0x1f]),
            Err(HeaderBlockError::Malformed)
        );
    }

    #[test]
    fn trailing_size_update_after_a_field_is_rejected() {
        // RFC 7541 §4.2 puts size updates at the start of a block.
        // `loona-hpack` rejects only an update that ends a block with fields;
        // one between fields is accepted, as httlib-hpack accepted both.
        // Changing either result is a guest-visible behavior change.
        let get = (b":method".to_vec(), b"GET".to_vec());
        assert_eq!(
            HeaderBlockDecoder::new(LIMITS).decode(&[0x82, 0x20]),
            Err(HeaderBlockError::Malformed)
        );
        assert_eq!(
            HeaderBlockDecoder::new(LIMITS).decode(&[0x82, 0x20, 0x82]),
            Ok(vec![get.clone(), get])
        );
    }

    #[test]
    fn dynamic_table_never_exceeds_the_limit() {
        // Insert 100 entries of 32 + 1 + 100 bytes: a 4096-byte table keeps
        // only the last 30 (4096 / 133), so index 62 + 30 is out of bounds.
        let mut block = Vec::new();
        for i in 0..100u8 {
            block.extend_from_slice(&[0x40, 0x01, b'a', 0x64]);
            block.extend_from_slice(&[i; 100]);
        }
        let mut decoder = HeaderBlockDecoder::new(LIMITS);
        assert_eq!(decoder.decode(&block).unwrap().len(), 100);
        assert_eq!(
            decoder.decode(&[0x80 | 62]).unwrap(),
            vec![(b"a".to_vec(), vec![99; 100])]
        );
        assert_eq!(
            decoder.decode(&[0x80 | (62 + 29)]).unwrap(),
            vec![(b"a".to_vec(), vec![70; 100])]
        );
        assert_eq!(
            decoder.decode(&[0x80 | (62 + 30)]),
            Err(HeaderBlockError::Malformed)
        );
    }

    #[test]
    fn field_limit_is_enforced_before_decoding() {
        // `00 80 80`: literal without indexing, empty Huffman name and value.
        let field = [0x00, 0x80, 0x80];
        let mut decoder = HeaderBlockDecoder::new(LIMITS);
        assert_eq!(decoder.decode(&field.repeat(1024)).unwrap().len(), 1024);
        let mut decoder = HeaderBlockDecoder::new(LIMITS);
        assert_eq!(
            decoder.decode(&field.repeat(64 * 1024 / 3)),
            Err(HeaderBlockError::TooManyFields)
        );
        // The last field has an invalid index, which only the decoder can see.
        // `TooManyFields` rather than `Malformed` proves it never ran.
        let mut block = field.repeat(1024);
        block.push(0x80 | 62);
        let mut decoder = HeaderBlockDecoder::new(LIMITS);
        assert_eq!(decoder.decode(&block), Err(HeaderBlockError::TooManyFields));
    }

    #[test]
    fn decoded_size_limit_is_enforced() {
        let limits = HeaderListLimits {
            max_fields: 1024,
            max_decoded_bytes: 100,
        };
        let mut block = Vec::new();
        Encoder::with_dynamic_size(4096)
            .encode(
                (b"x".to_vec(), vec![b'a'; 95], Encoder::NEVER_INDEXED),
                &mut block,
            )
            .unwrap();
        assert_eq!(
            HeaderBlockDecoder::new(limits).decode(&block),
            Ok(vec![(b"x".to_vec(), vec![b'a'; 95])])
        );
        block.push(0x82);
        assert_eq!(
            HeaderBlockDecoder::new(limits).decode(&block),
            Err(HeaderBlockError::TooLarge)
        );
    }
}
