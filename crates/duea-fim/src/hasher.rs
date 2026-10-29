use crate::types::{FileHash, FimConfig, HashAlgorithm};
use anyhow::Result;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Hasher {
    config: FimConfig,
}

impl Hasher {
    pub fn new(config: FimConfig) -> Self {
        Self { config }
    }

    pub fn hash_file(&self, path: &PathBuf) -> Result<FileHash> {
        FileHash::compute(path, self.config.hash_algorithm.clone())
    }

    pub fn hash_files(&self, paths: &[PathBuf]) -> Result<Vec<FileHash>> {
        let mut results = Vec::new();
        for path in paths {
            match self.hash_file(path) {
                Ok(hash) => results.push(hash),
                Err(e) => {
                    log::warn!("Failed to hash {}: {}", path.display(), e);
                }
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn hasher_hashes_files() {
        let config = FimConfig::default();
        let hasher = Hasher::new(config);

        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"test content").unwrap();
        let path = temp.path().to_path_buf();

        let hash = hasher.hash_file(&path).unwrap();
        assert!(!hash.hash.is_empty());
        assert_eq!(hash.size, 12);
    }
}