use crate::types::{FileHash, FimConfig};
use crate::hasher::Hasher;
use anyhow::Result;
use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use walkdir::WalkDir;

#[derive(Clone)]
pub struct Scanner {
    config: FimConfig,
    hasher: Hasher,
    baseline: Arc<Mutex<HashMap<PathBuf, FileHash>>>,
}

impl Scanner {
    pub fn new(config: FimConfig) -> Self {
        let hasher = Hasher::new(config.clone());
        Self {
            config,
            hasher,
            baseline: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn scan(&self) -> Result<Vec<FileHash>> {
        let mut files = Vec::new();

        for path in &self.config.paths {
            if !path.exists() {
                log::warn!("Scan path does not exist: {}", path.display());
                continue;
            }

            for entry in WalkDir::new(path)
                .follow_links(self.config.follow_symlinks)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path().to_path_buf();

                if self.should_exclude(&entry_path) {
                    continue;
                }

                if entry.metadata().map(|m| m.is_file()).unwrap_or(false) {
                    if let Some(max_size) = self.config.max_file_size {
                        if entry.metadata().map(|m| m.len() > max_size).unwrap_or(false) {
                            continue;
                        }
                    }
                    files.push(entry_path);
                }
            }
        }

        self.hasher.hash_files(&files)
    }

    /// Get a reference to the baseline for reading
    pub fn baseline(&self) -> &Arc<Mutex<HashMap<PathBuf, FileHash>>> {
        &self.baseline
    }

    pub async fn initialize_baseline(&self) -> Result<()> {
        let hashes = self.scan().await?;
        let mut baseline = self.baseline.lock().await;
        for hash in hashes {
            baseline.insert(hash.path.clone(), hash);
        }
        log::info!("Baseline initialized with {} files", baseline.len());
        Ok(())
    }

    pub async fn detect_changes(&self) -> Result<Vec<crate::types::FileChange>> {
        let current_hashes = self.scan().await?;
        let baseline = self.baseline.lock().await;
        let mut changes = Vec::new();

        let mut current_map = HashMap::new();
        for hash in current_hashes {
            current_map.insert(hash.path.clone(), hash);
        }

        for (path, baseline_hash) in baseline.iter() {
            match current_map.get(path) {
                Some(current_hash) => {
                    if current_hash.hash != baseline_hash.hash {
                        changes.push(crate::types::FileChange {
                            path: path.clone(),
                            change_type: crate::types::ChangeType::Modified,
                            old_hash: Some(baseline_hash.hash.clone()),
                            new_hash: Some(current_hash.hash.clone()),
                            timestamp: std::time::SystemTime::now(),
                            details: format!("File content changed: {}", path.display()),
                        });
                    }
                    if current_hash.permissions != baseline_hash.permissions {
                        changes.push(crate::types::FileChange {
                            path: path.clone(),
                            change_type: crate::types::ChangeType::PermissionsChanged,
                            old_hash: Some(baseline_hash.hash.clone()),
                            new_hash: Some(current_hash.hash.clone()),
                            timestamp: std::time::SystemTime::now(),
                            details: format!("File permissions changed: {}", path.display()),
                        });
                    }
                }
                None => {
                    changes.push(crate::types::FileChange {
                        path: path.clone(),
                        change_type: crate::types::ChangeType::Deleted,
                        old_hash: Some(baseline_hash.hash.clone()),
                        new_hash: None,
                        timestamp: std::time::SystemTime::now(),
                        details: format!("File deleted: {}", path.display()),
                    });
                }
            }
        }

        for (path, current_hash) in current_map.iter() {
            if !baseline.contains_key(path) {
                changes.push(crate::types::FileChange {
                    path: path.clone(),
                    change_type: crate::types::ChangeType::Created,
                    old_hash: None,
                    new_hash: Some(current_hash.hash.clone()),
                    timestamp: std::time::SystemTime::now(),
                    details: format!("File created: {}", path.display()),
                });
            }
        }

        Ok(changes)
    }

    pub async fn update_baseline(&self, changes: &[crate::types::FileChange]) -> Result<()> {
        let current_hashes = self.scan().await?;
        let mut baseline = self.baseline.lock().await;

        for change in changes {
            match change.change_type {
                crate::types::ChangeType::Created | crate::types::ChangeType::Modified => {
                    if let Some(hash) = current_hashes.iter().find(|h| h.path == change.path) {
                        baseline.insert(change.path.clone(), hash.clone());
                    }
                }
                crate::types::ChangeType::Deleted => {
                    baseline.remove(&change.path);
                }
                crate::types::ChangeType::PermissionsChanged => {
                    if let Some(hash) = current_hashes.iter().find(|h| h.path == change.path) {
                        baseline.insert(change.path.clone(), hash.clone());
                    }
                }
                crate::types::ChangeType::Moved { ref from } => {
                    if let Some(hash) = baseline.remove(from.as_path()) {
                        let mut new_hash = hash;
                        new_hash.path = change.path.clone();
                        baseline.insert(change.path.clone(), new_hash);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn should_exclude(&self, path: &PathBuf) -> bool {
        let path_str = path.to_string_lossy();
        for pattern in &self.config.exclude_patterns {
            if Self::match_pattern(&path_str, pattern) {
                return true;
            }
        }
        false
    }

    fn match_pattern(path: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            let regex_pattern = pattern
                .replace(".", "\\.")
                .replace("*", ".*");
            regex::Regex::new(&format!("^{}$", regex_pattern))
                .map(|re| re.is_match(path))
                .unwrap_or(false)
        } else {
            path.ends_with(pattern)
        }
    }

    pub async fn start_realtime_watcher(&self) -> Result<mpsc::Receiver<Event>> {
        let (tx, rx) = mpsc::channel(100);
        let config = NotifyConfig::default()
            .with_poll_interval(Duration::from_secs(1))
            .with_compare_contents(true);

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) {
                        let _ = tx.try_send(event);
                    }
                }
            },
            config,
        )?;

        for path in &self.config.paths {
            if path.exists() {
                watcher.watch(path, RecursiveMode::Recursive)?;
            }
        }

        std::mem::forget(watcher);
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;
    use std::io::Write;

    #[tokio::test]
    async fn scanner_scans_directory() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let mut f = fs::File::create(&test_file).unwrap();
        f.write_all(b"hello").unwrap();

        let config = FimConfig {
            paths: vec![temp_dir.path().to_path_buf()],
            ..Default::default()
        };

        let scanner = Scanner::new(config);
        let hashes = scanner.scan().await.unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].path, test_file);
    }

    #[tokio::test]
    async fn scanner_detects_changes() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let mut f = fs::File::create(&test_file).unwrap();
        f.write_all(b"hello").unwrap();

        let config = FimConfig {
            paths: vec![temp_dir.path().to_path_buf()],
            ..Default::default()
        };

        let scanner = Scanner::new(config);
        scanner.initialize_baseline().await.unwrap();

        fs::write(&test_file, b"modified").unwrap();

        let changes = scanner.detect_changes().await.unwrap();
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].change_type, crate::types::ChangeType::Modified));
    }

    #[test]
    fn matches_exclude_patterns() {
        let config = FimConfig {
            exclude_patterns: vec!["*.tmp".into(), "*.log".into()],
            ..Default::default()
        };
        let scanner = Scanner::new(config);

        assert!(scanner.should_exclude(&"/tmp/test.tmp".into()));
        assert!(scanner.should_exclude(&"/var/log/app.log".into()));
        assert!(!scanner.should_exclude(&"/etc/passwd".into()));
    }
}