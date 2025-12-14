use crate::Error;

/// Encode a chunk with its part metadata.
/// Format: "{part}/{total}|{payload}"
pub fn encode_part(part: usize, total: usize, data: &[u8]) -> Vec<u8> {
    let header = format!("{}/{}", part, total);
    let mut result = Vec::with_capacity(header.len() + 1 + data.len());
    result.extend_from_slice(header.as_bytes());
    result.push(b'|');
    result.extend_from_slice(data);
    result
}

/// Decode a chunk, extracting part number, total parts, and payload.
/// Returns (part, total, payload).
pub fn decode_part(data: &[u8]) -> Result<(usize, usize, Vec<u8>), Error> {
    // Find the '|' separator
    let separator_pos = data
        .iter()
        .position(|&b| b == b'|')
        .ok_or(Error::CorruptedSecret("missing separator".into()))?;

    let header = std::str::from_utf8(&data[..separator_pos])
        .map_err(|_| Error::CorruptedSecret("invalid header encoding".into()))?;

    // Parse "part/total"
    let slash_pos = header
        .find('/')
        .ok_or(Error::CorruptedSecret("missing slash in header".into()))?;

    let part: usize = header[..slash_pos]
        .parse()
        .map_err(|_| Error::CorruptedSecret("invalid part number".into()))?;

    let total: usize = header[slash_pos + 1..]
        .parse()
        .map_err(|_| Error::CorruptedSecret("invalid total number".into()))?;

    if part == 0 || part > total {
        return Err(Error::CorruptedSecret(format!(
            "invalid part {}/{}",
            part, total
        )));
    }

    let payload = data[separator_pos + 1..].to_vec();
    Ok((part, total, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let payload = b"hello world";
        let encoded = encode_part(2, 5, payload);
        let (part, total, decoded) = decode_part(&encoded).unwrap();

        assert_eq!(part, 2);
        assert_eq!(total, 5);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_encode_format() {
        let encoded = encode_part(1, 3, b"data");
        assert_eq!(&encoded, b"1/3|data");
    }

    #[test]
    fn test_decode_empty_payload() {
        let encoded = encode_part(1, 1, b"");
        let (part, total, payload) = decode_part(&encoded).unwrap();

        assert_eq!(part, 1);
        assert_eq!(total, 1);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_decode_binary_payload() {
        let binary_data: Vec<u8> = (0..=255).collect();
        let encoded = encode_part(1, 1, &binary_data);
        let (_, _, decoded) = decode_part(&encoded).unwrap();

        assert_eq!(decoded, binary_data);
    }

    #[test]
    fn test_decode_invalid_missing_separator() {
        let result = decode_part(b"1/3data");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_part_zero() {
        let result = decode_part(b"0/3|data");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_part_exceeds_total() {
        let result = decode_part(b"5/3|data");
        assert!(result.is_err());
    }
}
