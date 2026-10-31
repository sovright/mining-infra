//! The Prometheus textfile write shared by the sidecar and the P2P ingress.

use std::error::Error;
use std::fs;
use std::path::Path;

/// Replace `path` with `text`, so a collector never reads a half-written file.
/// This is blocking file I/O.
pub fn write_metrics_textfile(path: &Path, text: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, text)?;
    fs::rename(tmp, path)?;
    Ok(())
}
