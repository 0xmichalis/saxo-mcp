//! Configuration from the environment.
//!
//! Variables (also read from a `.env` file in the working directory):
//!   SAXO_ENV          — `sim` (default) or `live`.
//!   SAXO_APP_KEY      — the application's AppKey (OAuth client id). Required.
//!   SAXO_APP_SECRET   — the AppSecret, for apps registered with the Code grant.
//!                       Leave unset for PKCE apps, which have none.
//!   SAXO_REDIRECT_URI — the redirect URL registered for the app; must point at
//!                       localhost. Defaults to `http://localhost:8765/callback`.
//!   SAXO_TOKEN_FILE   — where the session tokens live. Defaults to
//!                       `$XDG_STATE_HOME/saxo-mcp/<env>-tokens.json`
//!                       (`~/.local/state/saxo-mcp/...` without XDG_STATE_HOME).

use std::fmt;
use std::path::PathBuf;

use reqwest::Url;

const DEFAULT_REDIRECT_URI: &str = "http://localhost:8765/callback";

/// The Saxo environment: the simulation sandbox or the real account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Sim,
    Live,
}

impl Environment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sim => "sim",
            Self::Live => "live",
        }
    }

    /// Base URL of the OpenAPI REST gateway.
    pub fn gateway_url(self) -> &'static str {
        match self {
            Self::Sim => "https://gateway.saxobank.com/sim/openapi",
            Self::Live => "https://gateway.saxobank.com/openapi",
        }
    }

    /// Base URL of the OAuth server (`/authorize`, `/token`).
    pub fn auth_url(self) -> &'static str {
        match self {
            Self::Sim => "https://sim.logonvalidation.net",
            Self::Live => "https://live.logonvalidation.net",
        }
    }
}

impl std::str::FromStr for Environment {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sim" => Ok(Self::Sim),
            "live" => Ok(Self::Live),
            other => Err(ConfigError(format!(
                "SAXO_ENV must be \"sim\" or \"live\", got {other:?}"
            ))),
        }
    }
}

/// A configuration problem, reported before anything talks to Saxo.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

/// Everything the server and the `auth` command need to reach Saxo.
#[derive(Clone)]
pub struct Config {
    pub env: Environment,
    pub app_key: String,
    pub app_secret: Option<String>,
    pub redirect_uri: Url,
    pub token_file: PathBuf,
    /// The REST gateway; [`Environment::gateway_url`] unless a test overrides it.
    pub gateway_url: String,
    /// The OAuth server; [`Environment::auth_url`] unless a test overrides it.
    pub auth_url: String,
}

/// Never prints the AppSecret.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("env", &self.env)
            .field("app_key", &self.app_key)
            .field(
                "app_secret",
                &self.app_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("redirect_uri", &self.redirect_uri.as_str())
            .field("token_file", &self.token_file)
            .field("gateway_url", &self.gateway_url)
            .field("auth_url", &self.auth_url)
            .finish()
    }
}

impl Config {
    /// Read the configuration from process environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Read the configuration through `lookup`, which returns a variable's value.
    /// Empty values count as unset.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let var = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());

        let env = match var("SAXO_ENV") {
            Some(value) => value.parse()?,
            None => Environment::Sim,
        };
        let app_key = var("SAXO_APP_KEY")
            .map(|key| key.trim().to_string())
            .ok_or_else(|| {
                ConfigError(
                    "SAXO_APP_KEY is not set: copy the AppKey of your Saxo OpenAPI \
                     application (developer.saxo → My Apps)"
                        .to_string(),
                )
            })?;
        let app_secret = var("SAXO_APP_SECRET");
        let redirect_uri = parse_redirect_uri(
            var("SAXO_REDIRECT_URI")
                .as_deref()
                .unwrap_or(DEFAULT_REDIRECT_URI),
        )?;
        let token_file = match var("SAXO_TOKEN_FILE") {
            Some(path) => PathBuf::from(path),
            None => default_token_file(env, var("XDG_STATE_HOME"), var("HOME"))?,
        };

        Ok(Self {
            env,
            app_key,
            app_secret,
            redirect_uri,
            token_file,
            gateway_url: env.gateway_url().to_string(),
            auth_url: env.auth_url().to_string(),
        })
    }
}

/// The redirect URL must be a plain-HTTP loopback address, since `saxo-mcp auth`
/// receives the authorization code on it.
fn parse_redirect_uri(value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value.trim())
        .map_err(|e| ConfigError(format!("SAXO_REDIRECT_URI is not a URL: {e}")))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1"));
    if url.scheme() != "http" || !loopback {
        return Err(ConfigError(format!(
            "SAXO_REDIRECT_URI must be http://localhost[:port]/path or \
             http://127.0.0.1[:port]/path, got {}",
            url.as_str()
        )));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ConfigError(
            "SAXO_REDIRECT_URI must not carry a query or fragment".to_string(),
        ));
    }
    if url.port().is_none() {
        return Err(ConfigError(format!(
            "SAXO_REDIRECT_URI needs the port `saxo-mcp auth` listens on, such as \
             http://localhost:8765/callback; PKCE apps register it without a port, \
             got {}",
            url.as_str()
        )));
    }
    Ok(url)
}

fn default_token_file(
    env: Environment,
    xdg_state_home: Option<String>,
    home: Option<String>,
) -> Result<PathBuf, ConfigError> {
    let state_dir = match (xdg_state_home, home) {
        (Some(state), _) => PathBuf::from(state),
        (None, Some(home)) => PathBuf::from(home).join(".local/state"),
        (None, None) => {
            return Err(ConfigError(
                "set SAXO_TOKEN_FILE: neither XDG_STATE_HOME nor HOME is set".to_string(),
            ));
        }
    };
    Ok(state_dir
        .join("saxo-mcp")
        .join(format!("{}-tokens.json", env.as_str())))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|name| vars.get(name).cloned())
    }

    #[test]
    fn defaults_to_sim_with_a_state_dir_token_file() {
        let config = config(&[("SAXO_APP_KEY", " key "), ("HOME", "/home/u")]).unwrap();
        assert_eq!(config.env, Environment::Sim);
        assert_eq!(config.app_key, "key");
        assert_eq!(config.app_secret, None);
        assert_eq!(
            config.redirect_uri.as_str(),
            "http://localhost:8765/callback"
        );
        assert_eq!(
            config.token_file,
            PathBuf::from("/home/u/.local/state/saxo-mcp/sim-tokens.json")
        );
        assert_eq!(
            config.gateway_url,
            "https://gateway.saxobank.com/sim/openapi"
        );
        assert_eq!(config.auth_url, "https://sim.logonvalidation.net");
    }

    #[test]
    fn live_uses_live_hosts_and_its_own_token_file() {
        let config = config(&[
            ("SAXO_ENV", "LIVE"),
            ("SAXO_APP_KEY", "key"),
            ("XDG_STATE_HOME", "/state"),
            ("HOME", "/home/u"),
        ])
        .unwrap();
        assert_eq!(config.env, Environment::Live);
        assert_eq!(config.gateway_url, "https://gateway.saxobank.com/openapi");
        assert_eq!(config.auth_url, "https://live.logonvalidation.net");
        assert_eq!(
            config.token_file,
            PathBuf::from("/state/saxo-mcp/live-tokens.json")
        );
    }

    #[test]
    fn explicit_token_file_and_secret_are_used() {
        let config = config(&[
            ("SAXO_APP_KEY", "key"),
            ("SAXO_APP_SECRET", "secret"),
            ("SAXO_TOKEN_FILE", "/data/tokens.json"),
            ("SAXO_REDIRECT_URI", "http://127.0.0.1:9000/cb"),
        ])
        .unwrap();
        assert_eq!(config.app_secret.as_deref(), Some("secret"));
        assert_eq!(config.token_file, PathBuf::from("/data/tokens.json"));
        assert_eq!(config.redirect_uri.as_str(), "http://127.0.0.1:9000/cb");
    }

    #[test]
    fn rejects_missing_app_key_and_unknown_env() {
        let err = config(&[("HOME", "/h"), ("SAXO_APP_KEY", "  ")]).unwrap_err();
        assert!(err.0.contains("SAXO_APP_KEY is not set"), "{err}");

        let err = config(&[("SAXO_ENV", "prod"), ("SAXO_APP_KEY", "k")]).unwrap_err();
        assert_eq!(err.0, "SAXO_ENV must be \"sim\" or \"live\", got \"prod\"");
    }

    #[test]
    fn rejects_redirects_that_leave_the_machine() {
        for uri in [
            "https://localhost:8765/callback",
            "http://example.com/callback",
            "http://localhost.example.com/callback",
            "http://localhost:8765/callback?x=1",
            "not a url",
        ] {
            let result = config(&[
                ("SAXO_APP_KEY", "k"),
                ("HOME", "/h"),
                ("SAXO_REDIRECT_URI", uri),
            ]);
            assert!(result.is_err(), "{uri} should be rejected");
        }
    }

    #[test]
    fn redirects_name_the_port_to_listen_on() {
        let err = config(&[
            ("SAXO_APP_KEY", "k"),
            ("HOME", "/h"),
            ("SAXO_REDIRECT_URI", "http://localhost/callback"),
        ])
        .unwrap_err();
        assert!(err.0.contains("port"), "{err}");

        for uri in ["http://127.0.0.1:9000/cb", "http://localhost:8765/callback"] {
            let config = config(&[
                ("SAXO_APP_KEY", "k"),
                ("HOME", "/h"),
                ("SAXO_REDIRECT_URI", uri),
            ])
            .unwrap();
            assert_eq!(config.redirect_uri.as_str(), uri);
        }
    }

    #[test]
    fn requires_somewhere_to_keep_tokens() {
        let err = config(&[("SAXO_APP_KEY", "k")]).unwrap_err();
        assert!(err.0.contains("SAXO_TOKEN_FILE"), "{err}");
    }

    #[test]
    fn debug_redacts_the_app_secret() {
        let config = config(&[
            ("SAXO_APP_KEY", "key"),
            ("SAXO_APP_SECRET", "SENTINEL-SECRET"),
            ("HOME", "/h"),
        ])
        .unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("SENTINEL-SECRET"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }
}
