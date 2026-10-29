use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHash {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    pub modified: SystemTime,
    pub permissions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub created_at: SystemTime,
    pub version: u32,
    pub files: HashMap<PathBuf, FileHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
    PermissionsChanged,
    Moved { from: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: PathBuf,
    pub change_type: ChangeType,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub timestamp: SystemTime,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: String,
    pub started_at: SystemTime,
    pub completed_at: SystemTime,
    pub files_scanned: usize,
    pub changes_detected: usize,
    pub changes: Vec<FileChange>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimConfig {
    pub paths: Vec<PathBuf>,
    pub exclude_patterns: Vec<String>,
    pub scan_interval_secs: u64,
    pub hash_algorithm: HashAlgorithm,
    pub follow_symlinks: bool,
    pub max_file_size: Option<u64>,
    pub real_time: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Blake3,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            paths: vec!["/etc".into(), "/var/log".into()],
            exclude_patterns: vec!["*.tmp".into(), "*.log".into(), "*.swp".into()],
            scan_interval_secs: 3600,
            hash_algorithm: HashAlgorithm::Sha256,
            follow_symlinks: false,
            max_file_size: Some(100 * 1024 * 1024),
            real_time: true,
        }
    }
}

impl FileHash {
    pub fn compute(path: &PathBuf, algorithm: HashAlgorithm) -> Result<Self> {
        let metadata = std::fs::metadata(path)?;
        let content = std::fs::read(path)?;

        let hash = match algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&content);
                format!("{:x}", hasher.finalize())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(&content);
                format!("{:x}", hasher.finalize())
            }
            HashAlgorithm::Blake3 => {
                let hash = blake3::hash(&content);
                hash.to_hex().to_string()
            }
        };

        let permissions = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                format!("{:o}", metadata.mode() & 0o777)
            }
            #[cfg(windows)]
            {
                // Windows doesn't have Unix-style permissions, use a default
                "644".to_string()
            }
        };

        Ok(FileHash {
            path: path.clone(),
            hash,
            size: metadata.len(),
            modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            permissions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn computes_sha256_hash() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"hello world").unwrap();
        let path = temp.path().to_path_buf();

        let file_hash = FileHash::compute(&path, HashAlgorithm::Sha256).unwrap();
        assert_eq!(file_hash.hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        assert_eq!(file_hash.size, 11);
    }

    #[test]
    fn computes_sha512_hash() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"hello world").unwrap();
        let path = temp.path().to_path_buf();

        let file_hash = FileHash::compute(&path, HashAlgorithm::Sha512).unwrap();
        assert_eq!(file_hash.hash.len(), 128);
    }

    #[test]
    fn computes_blake3_hash() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"hello world").unwrap();
        let path = temp.path().to_path_buf();

        let file_hash = FileHash::compute(&path, HashAlgorithm::Blake3).unwrap();
        assert_eq!(file_hash.hash.len(), 64);
    }
}