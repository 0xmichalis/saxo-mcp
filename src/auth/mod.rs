//! Saxo sessions: the OAuth login, the token file and keeping the session alive.
//!
//! Saxo access tokens are short-lived and each refresh rotates the refresh
//! token, whose own lifetime is short too. [`TokenManager`] hands out a valid
//! access token, refreshing under the token file's lock, and
//! [`TokenManager::keep_alive`] refreshes ahead of expiry so an idle server does
//! not let the session lapse between tool calls.

pub mod oauth;
pub mod store;

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::config::{Config, Environment};
pub use oauth::unix_now;
use oauth::{OAuthClient, OAuthError};
use store::{StoreError, TokenSet};

/// Hand out access tokens with at least this many seconds left, so a request
/// does not expire in flight.
const MIN_VALIDITY_SECS: u64 = 60;
/// [`TokenManager::keep_alive`] refreshes this long before the access token expires.
const KEEP_ALIVE_LEAD_SECS: u64 = 120;
/// Shortest pause between background refreshes, should Saxo ever issue access
/// tokens that live less than the lead time.
const KEEP_ALIVE_MIN_DELAY: Duration = Duration::from_secs(30);
/// After a failed background refresh, try again after this long.
const KEEP_ALIVE_RETRY: Duration = Duration::from_secs(60);
/// While signed out, look for a new login this often. Reading the token file
/// is all this costs; a refresh token Saxo refused is not sent again.
const KEEP_ALIVE_SIGNED_OUT_POLL: Duration = Duration::from_secs(300);

/// Why no access token is available.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error(
        "not signed in to Saxo {env}: run `saxo-mcp auth` (token file {})",
        token_file.display()
    )]
    NotSignedIn {
        env: &'static str,
        token_file: PathBuf,
    },
    #[error("{0}")]
    WrongSession(String),
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl AuthError {
    /// Whether only a new login can fix this, so retrying is pointless.
    pub fn needs_login(&self) -> bool {
        matches!(
            self,
            Self::NotSignedIn { .. }
                | Self::WrongSession(_)
                | Self::OAuth(OAuthError::SessionEnded(_))
        )
    }
}

/// When the current session's tokens expire, without the tokens themselves.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SessionStatus {
    pub env: Environment,
    pub access_expires_at: u64,
    pub refresh_expires_at: Option<u64>,
}

/// Hands out valid access tokens for one environment's token file.
pub struct TokenManager {
    oauth: OAuthClient,
    env: Environment,
    app_key: String,
    token_file: PathBuf,
    /// The mutex also serializes this process's refreshes; the file lock
    /// serializes them across processes.
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// The last tokens this process saw.
    cached: Option<TokenSet>,
    /// A refresh token Saxo refused. Until a new login replaces it in the token
    /// file, the session is known to be over without asking Saxo again.
    refused_refresh: Option<String>,
}

impl TokenManager {
    pub fn new(config: &Config) -> Result<Self, OAuthError> {
        Ok(Self {
            oauth: OAuthClient::new(config)?,
            env: config.env,
            app_key: config.app_key.clone(),
            token_file: config.token_file.clone(),
            state: Mutex::new(State::default()),
        })
    }

    /// A valid access token, refreshing the session if needed.
    pub async fn access_token(&self) -> Result<String, AuthError> {
        Ok(self
            .valid_tokens(MIN_VALIDITY_SECS, None)
            .await?
            .access_token)
    }

    /// A different access token than `rejected`, which Saxo answered with 401.
    /// Uses a token another process saved since, or refreshes the session.
    pub async fn replace_rejected(&self, rejected: &str) -> Result<String, AuthError> {
        Ok(self
            .valid_tokens(MIN_VALIDITY_SECS, Some(rejected))
            .await?
            .access_token)
    }

    /// Expiry times of the current session, refreshing it first if needed.
    pub async fn status(&self) -> Result<SessionStatus, AuthError> {
        let tokens = self.valid_tokens(MIN_VALIDITY_SECS, None).await?;
        Ok(SessionStatus {
            env: tokens.env,
            access_expires_at: tokens.access_expires_at,
            refresh_expires_at: tokens.refresh_expires_at,
        })
    }

    /// Refresh ahead of every access-token expiry, forever: while signed out,
    /// wait for a new login to appear in the token file. Reports changes in
    /// state on stderr.
    pub async fn keep_alive(&self) {
        let mut last_problem: Option<String> = None;
        loop {
            let (delay, problem) = match self.valid_tokens(KEEP_ALIVE_LEAD_SECS, None).await {
                Ok(tokens) => {
                    let until_lead = tokens
                        .access_expires_at
                        .saturating_sub(KEEP_ALIVE_LEAD_SECS)
                        .saturating_sub(unix_now());
                    (
                        Duration::from_secs(until_lead).max(KEEP_ALIVE_MIN_DELAY),
                        None,
                    )
                }
                Err(e) if e.needs_login() => (KEEP_ALIVE_SIGNED_OUT_POLL, Some(e.to_string())),
                Err(e) => (
                    KEEP_ALIVE_RETRY,
                    Some(format!("refresh failed, retrying: {e}")),
                ),
            };
            if problem != last_problem {
                match &problem {
                    Some(problem) => eprintln!("saxo-mcp: {problem}"),
                    None if last_problem.is_some() => eprintln!("saxo-mcp: Saxo session active"),
                    None => {}
                }
                last_problem = problem;
            }
            tokio::time::sleep(delay).await;
        }
    }

    /// Tokens whose access token stays valid for `margin` seconds and is not
    /// `rejected`, from this process's cache, the token file, or a refresh.
    async fn valid_tokens(
        &self,
        margin: u64,
        rejected: Option<&str>,
    ) -> Result<TokenSet, AuthError> {
        let usable = |t: &TokenSet| {
            t.access_valid_for(unix_now(), margin) && Some(t.access_token.as_str()) != rejected
        };

        let mut state = self.state.lock().await;
        if let Some(tokens) = state.cached.as_ref().filter(|t| usable(t)) {
            return Ok(tokens.clone());
        }
        state.cached = None;

        let _lock = store::lock(&self.token_file).await?;
        let Some(stored) = store::load(&self.token_file)? else {
            return Err(AuthError::NotSignedIn {
                env: self.env.as_str(),
                token_file: self.token_file.clone(),
            });
        };
        self.check_owner(&stored)?;
        if usable(&stored) {
            state.cached = Some(stored.clone());
            return Ok(stored);
        }
        let ended = |why: &str| AuthError::from(OAuthError::SessionEnded(why.to_string()));
        if stored.refresh_expired(unix_now()) {
            return Err(ended("the refresh token has expired"));
        }
        if state.refused_refresh.as_deref() == Some(stored.refresh_token.as_str()) {
            return Err(ended("Saxo refused the refresh token earlier"));
        }

        let fresh = match self.oauth.refresh(&stored).await {
            Ok(fresh) => fresh,
            Err(e) => {
                if matches!(e, OAuthError::SessionEnded(_)) {
                    state.refused_refresh = Some(stored.refresh_token);
                }
                return Err(e.into());
            }
        };
        store::save(&self.token_file, &fresh)?;
        state.cached = Some(fresh.clone());
        Ok(fresh)
    }

    /// Refuse tokens issued for another environment or application, which
    /// Saxo would reject anyway, with a clearer message.
    fn check_owner(&self, tokens: &TokenSet) -> Result<(), AuthError> {
        if tokens.env != self.env || tokens.app_key != self.app_key {
            return Err(AuthError::WrongSession(format!(
                "{} holds a {} session for another AppKey or environment than \
                 SAXO_ENV={} and SAXO_APP_KEY; run `saxo-mcp auth` or point \
                 SAXO_TOKEN_FILE elsewhere",
                self.token_file.display(),
                tokens.env.as_str(),
                self.env.as_str()
            )));
        }
        Ok(())
    }
}

/// Sign in interactively and save the new session, replacing any old one.
pub async fn login(config: &Config, on_url: impl FnMut(&str)) -> Result<SessionStatus, AuthError> {
    let tokens = OAuthClient::new(config)?.login(on_url).await?;
    let _lock = store::lock(&config.token_file).await?;
    store::save(&config.token_file, &tokens)?;
    Ok(SessionStatus {
        env: tokens.env,
        access_expires_at: tokens.access_expires_at,
        refresh_expires_at: tokens.refresh_expires_at,
    })
}
