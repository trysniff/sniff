use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, BufWriter, Write};

pub(in crate::benchmark::release) fn sha256_json(value: &impl Serialize) -> Result<String, String> {
    let mut writer = BufWriter::with_capacity(64 * 1024, Sha256Writer(Sha256::new()));
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| format!("failed to serialize canonical JSON: {error}"))?;
    let writer = writer
        .into_inner()
        .map_err(|error| format!("failed to hash canonical JSON: {error}"))?;
    Ok(format!("{:x}", writer.0.finalize()))
}

struct Sha256Writer(Sha256);

impl Write for Sha256Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamed_hash_matches_canonical_json_bytes() {
        let value = (
            serde_json::json!({"nested": [null, 17, "quoted \\\" text", "\u{1f43d}"]}),
            "x".repeat(1024 * 1024),
        );
        let old_bytes = serde_json::to_vec(&value).unwrap();
        let old_hash = format!("{:x}", Sha256::digest(old_bytes));
        assert_eq!(sha256_json(&value).unwrap(), old_hash);
    }
}
