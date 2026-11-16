//! The session tokens on disk.
//!
//! One JSON file per environment, readable only by its owner. Saxo rotates the
//! refresh token on every use and invalidates the previous one, so every process
//! sharing the file (each Hermes profile runs its own server) must refresh under
//! an exclusive lock and re-read the file first: a process that refreshed with a
//! stale copy would present an already-rotated token and end the session.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Environment;

/// The tokens of one signed-in session. Times are Unix seconds.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSet {
    pub env: Environment,
    /// The application the tokens were issued to.
    pub app_key: String,
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    /// When the refresh token expires, if Saxo said.
    pub refresh_expires_at: Option<u64>,
    /// The login's PKCE verifier, which Saxo asks for again on refresh.
    #[serde(default)]
    pub code_verifier: Option<String>,
}

/// Never prints the tokens.
impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSet")
            .field("env", &self.env)
            .field("app_key", &self.app_key)
            .field("access_token", &"<redacted>")
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_token", &"<redacted>")
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field(
                "code_verifier",
                &self.code_verifier.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl TokenSet {
    /// Whether the access token stays valid for at least `margin` seconds after `now`.
    pub fn access_valid_for(&self, now: u64, margin: u64) -> bool {
        self.access_expires_at > now.saturating_add(margin)
    }

    /// Whether the refresh token is known to have expired at `now`.
    pub fn refresh_expired(&self, now: u64) -> bool {
        self.refresh_expires_at.is_some_and(|at| at <= now)
    }
}

/// An error reading or writing the token file. Carries paths, never contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct StoreError(pub String);

/// Read the token file; `None` if it does not exist yet.
pub fn load(path: &Path) -> Result<Option<TokenSet>, StoreError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error("reading", path, &e)),
    };
    serde_json::from_str(&text).map(Some).map_err(|e| {
        StoreError(format!(
            "{} is not a saxo-mcp token file ({}); run `saxo-mcp auth` to replace it",
            path.display(),
            json_problem(&e)
        ))
    })
}

/// Replace the token file atomically: write a private temporary file next to it,
/// flush it to disk, then rename it over the old one.
pub fn save(path: &Path, tokens: &TokenSet) -> Result<(), StoreError> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| io_error("creating", dir, &e))?;
    }
    let json = serde_json::to_vec_pretty(tokens)
        .map_err(|e| StoreError(format!("encoding tokens: {}", json_problem(&e))))?;

    let tmp = sibling(path, "tmp");
    let write = || -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&json)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_error("writing", path, &e)
    })
}

/// An exclusive lock over the token file, held until dropped. It lives in a
/// separate `.lock` file because the token file itself is replaced by rename.
pub struct FileLock {
    _file: File,
}

/// Wait for the exclusive lock over `path`'s token file.
pub async fn lock(path: &Path) -> Result<FileLock, StoreError> {
    let lock_path = sibling(path, "lock");
    if let Some(dir) = lock_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| io_error("creating", dir, &e))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| io_error("opening", &lock_path, &e))?;
    // `File::lock` blocks the thread, so wait on a blocking-pool thread.
    tokio::task::spawn_blocking(move || file.lock().map(|()| FileLock { _file: file }))
        .await
        .map_err(|e| StoreError(format!("waiting for the token lock: {e}")))?
        .map_err(|e| io_error("locking", &lock_path, &e))
}

fn sibling(path: &Path, extension: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(extension);
    path.with_file_name(name)
}

/// Describe a JSON error by position only: serde's messages can quote the values
/// they failed on, and those values are tokens.
fn json_problem(e: &serde_json::Error) -> String {
    format!(
        "{:?} error at line {} column {}",
        e.classify(),
        e.line(),
        e.column()
    )
}

fn io_error(action: &str, path: &Path, e: &io::Error) -> StoreError {
    StoreError(format!("{action} {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use super::*;

    fn tokens() -> TokenSet {
        TokenSet {
            env: Environment::Sim,
            app_key: "app".to_string(),
            access_token: "ACCESS-SENTINEL".to_string(),
            access_expires_at: 2_000,
            refresh_token: "REFRESH-SENTINEL".to_string(),
            refresh_expires_at: Some(3_000),
            code_verifier: Some("VERIFIER-SENTINEL".to_string()),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("saxo-mcp-store-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn save_then_load_round_trips_with_private_permissions() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("nested/sim-tokens.json");

        assert_eq!(load(&path).unwrap(), None);
        save(&path, &tokens()).unwrap();
        assert_eq!(load(&path).unwrap(), Some(tokens()));

        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert!(!sibling(&path, "tmp").exists());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn load_rejects_foreign_files_without_echoing_them() {
        let dir = temp_dir("foreign");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tokens.json");
        // serde_json's own message would quote the mistyped value.
        fs::write(
            &path,
            r#"{"env":"sim","app_key":"a","access_token":"t","access_expires_at":"LEAKED-SENTINEL"}"#,
        )
        .unwrap();

        let err = load(&path).unwrap_err();
        assert!(err.0.contains("not a saxo-mcp token file"), "{err}");
        assert!(!err.0.contains("LEAKED-SENTINEL"), "{err}");

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn debug_redacts_tokens() {
        let debug = format!("{:?}", tokens());
        assert!(!debug.contains("SENTINEL"), "{debug}");
    }

    #[test]
    fn validity_checks_respect_the_margin() {
        let t = tokens();
        assert!(t.access_valid_for(1_000, 60));
        assert!(!t.access_valid_for(1_940, 60));
        assert!(!t.refresh_expired(2_999));
        assert!(t.refresh_expired(3_000));
        let unknown = TokenSet {
            refresh_expires_at: None,
            ..t
        };
        assert!(!unknown.refresh_expired(u64::MAX));
    }

    #[tokio::test]
    async fn lock_is_exclusive_until_dropped() {
        let dir = temp_dir("lock");
        let path = dir.join("tokens.json");

        let held = lock(&path).await.unwrap();
        let waiter = tokio::spawn({
            let path = path.clone();
            async move { lock(&path).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiter.is_finished(), "second lock must wait");

        drop(held);
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("lock released")
            .unwrap()
            .unwrap();

        fs::remove_dir_all(dir).unwrap();
    }
}
