//! Saxo's OAuth 2.0 Authorization Code flow with PKCE.
//!
//! `saxo-mcp auth` sends the user to Saxo's login page and receives the
//! authorization code on a loopback redirect. The code, and later each refresh
//! token, is exchanged at the token endpoint. Errors carry OAuth error codes and
//! HTTP statuses, never request or response bodies, which hold credentials.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::store::TokenSet;
use crate::config::{Config, Environment};

const USER_AGENT: &str = concat!("saxo-mcp/", env!("CARGO_PKG_VERSION"));
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// How long `saxo-mcp auth` waits for the browser to come back.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Bounds a single callback request, so a stuck client cannot stall the login.
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_HEAD: usize = 16 * 1024;

/// An OAuth failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuthError {
    /// Saxo refused the grant: the refresh token expired, was rotated away or
    /// was revoked. Only a new login helps.
    #[error("the Saxo session has ended ({0}); sign in again with `saxo-mcp auth`")]
    SessionEnded(String),
    /// The token endpoint answered with another error.
    #[error("Saxo's token endpoint returned {0}")]
    Rejected(String),
    /// The login in the browser did not complete.
    #[error("{0}")]
    Login(String),
    #[error("{0}")]
    Transport(String),
}

/// The token endpoint's answer. Lifetimes are seconds; Saxo documents that
/// `expires_in` can be negative when a code is redeemed late.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
    refresh_token: String,
    refresh_token_expires_in: Option<i64>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: Option<String>,
}

/// Talks to Saxo's token endpoint for one application.
#[derive(Clone)]
pub struct OAuthClient {
    http: reqwest::Client,
    env: Environment,
    auth_url: String,
    app_key: String,
    app_secret: Option<String>,
    redirect_uri: Url,
}

impl OAuthClient {
    pub fn new(config: &Config) -> Result<Self, OAuthError> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| OAuthError::Transport(format!("building HTTP client: {e}")))?;
        Ok(Self {
            http,
            env: config.env,
            auth_url: config.auth_url.trim_end_matches('/').to_string(),
            app_key: config.app_key.clone(),
            app_secret: config.app_secret.clone(),
            redirect_uri: config.redirect_uri.clone(),
        })
    }

    /// The login page URL for a PKCE challenge and CSRF `state`.
    pub fn authorize_url(&self, challenge: &str, state: &str) -> String {
        let mut url =
            Url::parse(&format!("{}/authorize", self.auth_url)).expect("auth URL is a valid base");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.app_key)
            .append_pair("redirect_uri", self.redirect_uri.as_str())
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        url.into()
    }

    /// Exchange an authorization code for a session.
    pub async fn exchange_code(&self, code: &str, verifier: &str) -> Result<TokenSet, OAuthError> {
        let form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("code_verifier", verifier),
        ];
        self.token_request(form, Some(verifier), false).await
    }

    /// Trade a session's refresh token for new tokens. Saxo invalidates the old
    /// refresh token as soon as it answers, so the result must be saved before
    /// anything else uses it.
    pub async fn refresh(&self, session: &TokenSet) -> Result<TokenSet, OAuthError> {
        // Saxo's PKCE guide sends the login's code_verifier with refreshes and its
        // samples send redirect_uri; sending both satisfies either reading.
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", session.refresh_token.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
        ];
        if let Some(verifier) = &session.code_verifier {
            form.push(("code_verifier", verifier));
        }
        self.token_request(form, session.code_verifier.as_deref(), true)
            .await
    }

    async fn token_request(
        &self,
        mut form: Vec<(&str, &str)>,
        code_verifier: Option<&str>,
        refreshing: bool,
    ) -> Result<TokenSet, OAuthError> {
        let mut request = self.http.post(format!("{}/token", self.auth_url));
        // Apps with an AppSecret authenticate with it; PKCE apps identify
        // themselves by client_id alone.
        match &self.app_secret {
            Some(secret) => request = request.basic_auth(&self.app_key, Some(secret)),
            None => form.push(("client_id", &self.app_key)),
        }
        let response = request.form(&form).send().await.map_err(|e| {
            OAuthError::Transport(format!("token request failed: {}", e.without_url()))
        })?;
        let status = response.status();
        let body = response.text().await.map_err(|e| {
            OAuthError::Transport(format!("reading token response: {}", e.without_url()))
        })?;

        if !status.is_success() {
            let code = serde_json::from_str::<ErrorResponse>(&body)
                .ok()
                .and_then(|e| e.error)
                .filter(|code| is_oauth_code(code));
            let detail = match &code {
                Some(code) => format!("HTTP {status} ({code})"),
                None => format!("HTTP {status}"),
            };
            // Saxo answers a dead refresh token with a bare `400 Bad Request`
            // page rather than an OAuth error object.
            let refused = matches!(status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED);
            return Err(if refreshing && refused {
                OAuthError::SessionEnded(detail)
            } else {
                OAuthError::Rejected(detail)
            });
        }

        let tokens: TokenResponse = serde_json::from_str(&body).map_err(|e| {
            OAuthError::Rejected(format!(
                "an unreadable token response ({:?} error at line {} column {})",
                e.classify(),
                e.line(),
                e.column()
            ))
        })?;
        let at = |secs: i64| unix_now().saturating_add_signed(secs);
        Ok(TokenSet {
            env: self.env,
            app_key: self.app_key.clone(),
            access_token: tokens.access_token,
            access_expires_at: at(tokens.expires_in),
            refresh_token: tokens.refresh_token,
            refresh_expires_at: tokens.refresh_token_expires_in.map(at),
            code_verifier: code_verifier.map(str::to_string),
        })
    }

    /// Run the interactive login: print the login URL, wait for Saxo to redirect
    /// the browser to the loopback address, then exchange the code.
    pub async fn login(&self, mut on_url: impl FnMut(&str)) -> Result<TokenSet, OAuthError> {
        let port = self.redirect_uri.port_or_known_default().unwrap_or(80);
        let listener = TcpListener::bind(("127.0.0.1", port)).await.map_err(|e| {
            OAuthError::Login(format!(
                "cannot listen on 127.0.0.1:{port} for the login redirect: {e}"
            ))
        })?;

        let pkce = Pkce::generate()?;
        let state = random_token(16)?;
        on_url(&self.authorize_url(&pkce.challenge, &state));

        let code = tokio::time::timeout(
            LOGIN_TIMEOUT,
            receive_code(&listener, self.redirect_uri.path(), &state),
        )
        .await
        .map_err(|_| {
            OAuthError::Login(format!(
                "no login redirect within {} minutes",
                LOGIN_TIMEOUT.as_secs() / 60
            ))
        })??;
        self.exchange_code(&code, &pkce.verifier).await
    }
}

/// A PKCE verifier and its S256 challenge.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn generate() -> Result<Self, OAuthError> {
        let verifier = random_token(32)?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Ok(Self {
            verifier,
            challenge,
        })
    }
}

/// `bytes` random bytes from the OS, base64url-encoded.
fn random_token(bytes: usize) -> Result<String, OAuthError> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf)
        .map_err(|e| OAuthError::Login(format!("no randomness from the OS: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// OAuth error codes are short ASCII identifiers; anything else is not echoed.
fn is_oauth_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What a request to the loopback listener carried.
#[derive(Debug, PartialEq, Eq)]
enum Callback {
    Code(String),
    /// Saxo redirected with an error, e.g. the user declined.
    Denied(String),
    /// Not the login redirect (wrong path, stale state, a favicon request).
    Ignored(&'static str),
}

/// Serve the loopback listener until the login redirect arrives.
async fn receive_code(
    listener: &TcpListener,
    path: &str,
    state: &str,
) -> Result<String, OAuthError> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| OAuthError::Login(format!("accepting the login redirect: {e}")))?;
        let head = match tokio::time::timeout(CALLBACK_READ_TIMEOUT, read_head(&mut stream)).await {
            Ok(Some(head)) => head,
            _ => continue,
        };
        let callback = parse_callback(&head, path, state);
        let (status, message) = match &callback {
            Callback::Code(_) => ("200 OK", "Signed in to Saxo. You can close this tab."),
            Callback::Denied(_) => (
                "400 Bad Request",
                "Saxo did not grant access. See the terminal for details.",
            ),
            Callback::Ignored(_) => ("404 Not Found", "Not found."),
        };
        respond(&mut stream, status, message).await;
        match callback {
            Callback::Code(code) => return Ok(code),
            Callback::Denied(error) => {
                return Err(OAuthError::Login(format!("Saxo denied the login: {error}")));
            }
            Callback::Ignored(_) => {}
        }
    }
}

async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 || buf.len() + n > MAX_REQUEST_HEAD {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8(buf).ok()
}

fn parse_callback(head: &str, path: &str, state: &str) -> Callback {
    let mut request_line = head.lines().next().unwrap_or_default().split(' ');
    let (Some("GET"), Some(target)) = (request_line.next(), request_line.next()) else {
        return Callback::Ignored("not a GET request");
    };
    let Ok(url) = Url::parse("http://localhost").and_then(|base| base.join(target)) else {
        return Callback::Ignored("unparsable request target");
    };
    if url.path() != path {
        return Callback::Ignored("not the redirect path");
    }
    let param = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    if param("state").as_deref() != Some(state) {
        return Callback::Ignored("state does not match this login");
    }
    if let Some(error) = param("error") {
        let error = if is_oauth_code(&error) {
            error
        } else {
            "unrecognised error".to_string()
        };
        return Callback::Denied(error);
    }
    match param("code") {
        Some(code) if !code.is_empty() => Callback::Code(code),
        _ => Callback::Ignored("no code in the redirect"),
    }
}

async fn respond(stream: &mut TcpStream, status: &str, message: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         X-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{message}",
        message.len()
    );
    // The browser may already be gone; the outcome is reported in the terminal.
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_the_s256_of_the_verifier() {
        // RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");

        let pkce = Pkce::generate().unwrap();
        assert_eq!(pkce.verifier.len(), 43);
        assert_eq!(
            pkce.challenge,
            URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.verifier.as_bytes()))
        );
        assert_ne!(Pkce::generate().unwrap().verifier, pkce.verifier);
    }

    #[test]
    fn callback_yields_the_code_only_for_this_login() {
        let ok = "GET /callback?code=abc%2Fdef&state=s1 HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(
            parse_callback(ok, "/callback", "s1"),
            Callback::Code("abc/def".to_string())
        );
        assert_eq!(
            parse_callback(ok, "/callback", "s2"),
            Callback::Ignored("state does not match this login")
        );
        assert_eq!(
            parse_callback("GET /favicon.ico HTTP/1.1\r\n\r\n", "/callback", "s1"),
            Callback::Ignored("not the redirect path")
        );
        assert_eq!(
            parse_callback(
                "POST /callback?code=x&state=s1 HTTP/1.1\r\n\r\n",
                "/callback",
                "s1"
            ),
            Callback::Ignored("not a GET request")
        );
        assert_eq!(
            parse_callback("GET /callback?state=s1 HTTP/1.1\r\n\r\n", "/callback", "s1"),
            Callback::Ignored("no code in the redirect")
        );
    }

    #[test]
    fn callback_reports_denials_without_echoing_free_text() {
        let denied = "GET /callback?error=access_denied&state=s1 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_callback(denied, "/callback", "s1"),
            Callback::Denied("access_denied".to_string())
        );
        let odd = "GET /callback?error=%3Cscript%3E&state=s1 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_callback(odd, "/callback", "s1"),
            Callback::Denied("unrecognised error".to_string())
        );
    }

    #[test]
    fn oauth_codes_are_short_identifiers() {
        assert!(is_oauth_code("invalid_grant"));
        assert!(!is_oauth_code(""));
        assert!(!is_oauth_code("token abc expired"));
        assert!(!is_oauth_code(&"a".repeat(65)));
    }
}
