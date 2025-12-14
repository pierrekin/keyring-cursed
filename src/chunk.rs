/// Returns the maximum payload size per chunk for the current platform.
/// This accounts for the metadata header overhead.
pub fn max_chunk_size() -> usize {
    max_raw_size() - max_header_overhead()
}

/// Maximum raw secret size the platform can store per entry.
fn max_raw_size() -> usize {
    #[cfg(target_os = "windows")]
    {
        2048 // Windows Credential Manager ~2.5KB limit, leave margin
    }

    #[cfg(target_os = "macos")]
    {
        16384 // macOS keychain practical limit
    }

    #[cfg(target_os = "ios")]
    {
        16384
    }

    #[cfg(target_os = "linux")]
    {
        8192 // Secret Service varies, conservative default
    }

    #[cfg(not(any(
        target_os = "windows",
        target_os = "macos",
        target_os = "ios",
        target_os = "linux"
    )))]
    {
        2048 // Safe fallback for unknown platforms
    }
}

/// Maximum overhead for the header format "{part}/{total}|"
/// Assuming up to 9999 parts, header is at most "9999/9999|" = 10 bytes
fn max_header_overhead() -> usize {
    10
}

/// Calculate how many chunks are needed for a given data size.
pub fn chunks_needed(data_len: usize) -> usize {
    if data_len == 0 {
        return 1; // Even empty data needs one chunk
    }
    let chunk_size = max_chunk_size();
    (data_len + chunk_size - 1) / chunk_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunks_needed() {
        let chunk_size = max_chunk_size();

        assert_eq!(chunks_needed(0), 1);
        assert_eq!(chunks_needed(1), 1);
        assert_eq!(chunks_needed(chunk_size), 1);
        assert_eq!(chunks_needed(chunk_size + 1), 2);
        assert_eq!(chunks_needed(chunk_size * 3), 3);
        assert_eq!(chunks_needed(chunk_size * 3 + 1), 4);
    }

    #[test]
    fn test_max_chunk_size_is_positive() {
        assert!(max_chunk_size() > 0);
        assert!(max_chunk_size() >= 1000); // Should be at least 1KB usable
    }
}
