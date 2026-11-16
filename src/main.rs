//! Entry point.
//!
//!   saxo-mcp        serve the MCP server over stdio
//!   saxo-mcp auth   sign in to Saxo in a browser and save the session
//!
//! Configuration comes from environment variables, also loaded from a `.env`
//! file in the working directory; see `config.rs` and the README.

use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;

use rmcp::ServiceExt;
use rmcp::transport::stdio;
use saxo_mcp::auth::{self, TokenManager, unix_now};
use saxo_mcp::config::Config;
use saxo_mcp::mcp::SaxoServer;
use saxo_mcp::saxo::SaxoClient;

const USAGE: &str = "usage: saxo-mcp [auth]

  (no command)  serve the read-only Saxo MCP server over stdio
  auth          sign in to Saxo in a browser and save the session

Configuration: SAXO_ENV, SAXO_APP_KEY, SAXO_APP_SECRET, SAXO_REDIRECT_URI,
SAXO_TOKEN_FILE (environment or .env). See the README.";

#[tokio::main]
async fn main() -> ExitCode {
    // Real environment variables take precedence over the .env file.
    dotenvy::dotenv().ok();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [] => serve().await,
        ["auth"] => login().await,
        ["-h" | "--help" | "help"] => {
            println!("{USAGE}");
            Ok(())
        }
        ["-V" | "--version"] => {
            println!("saxo-mcp {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("saxo-mcp: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn serve() -> Result<(), String> {
    let config = Config::from_env().map_err(|e| e.to_string())?;
    let tokens = Arc::new(TokenManager::new(&config).map_err(|e| e.to_string())?);
    let client = SaxoClient::new(&config.gateway_url, tokens.clone()).map_err(|e| e.to_string())?;
    let server = SaxoServer::new(client, config.env);

    // Keep the session alive while the server runs, so it survives idle hours
    // between tool calls. A signed-out start is fine: tools report it, and a
    // later `saxo-mcp auth` is picked up without a restart.
    tokio::spawn(async move { tokens.keep_alive().await });

    // stdout carries the MCP protocol; diagnostics go to stderr.
    let service = server.serve(stdio()).await.map_err(|e| e.to_string())?;
    service.waiting().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn login() -> Result<(), String> {
    let config = Config::from_env().map_err(|e| e.to_string())?;
    eprintln!(
        "Signing in to Saxo {} as AppKey {} with redirect {}",
        config.env.as_str(),
        config.app_key,
        config.redirect_uri
    );
    let status = auth::login(&config, |url| {
        eprintln!("\nOpen this URL in a browser and sign in:\n\n  {url}\n");
        if open_in_browser(url) {
            eprintln!("Opened it in your default browser.");
        }
        eprintln!("Waiting for Saxo to redirect back...");
    })
    .await
    .map_err(|e| e.to_string())?;

    eprintln!(
        "Signed in. Session saved to {} (access token valid for {}s{}).",
        config.token_file.display(),
        status.access_expires_at.saturating_sub(unix_now()),
        status
            .refresh_expires_at
            .map(|at| format!(", refresh token for {}s", at.saturating_sub(unix_now())))
            .unwrap_or_default()
    );
    Ok(())
}

/// Hand `url` to the desktop's browser. Returns whether an opener started; the
/// printed URL remains the fallback.
fn open_in_browser(url: &str) -> bool {
    let set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
    let Some(opener) = browser_opener(std::env::consts::OS, set) else {
        return false;
    };
    let child = Command::new(opener)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match child {
        // An opener may run as long as the browser it starts; reap it whenever.
        Ok(mut child) => {
            std::thread::spawn(move || child.wait());
            true
        }
        Err(_) => false,
    }
}

/// The command that opens a URL on this machine's desktop, if it has one. In an
/// SSH session the browser belongs on the other end of the tunnel, and a
/// terminal-only host would get a text browser in place of the prompt.
fn browser_opener(os: &str, set: impl Fn(&str) -> bool) -> Option<&'static str> {
    if set("SSH_CONNECTION") || set("SSH_TTY") {
        return None;
    }
    match os {
        "macos" => Some("open"),
        "linux" | "freebsd" | "openbsd" | "netbsd" => {
            (set("DISPLAY") || set("WAYLAND_DISPLAY")).then_some("xdg-open")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars<'a>(set: &'a [&'a str]) -> impl Fn(&str) -> bool + 'a {
        move |name| set.contains(&name)
    }

    #[test]
    fn opens_a_browser_only_on_a_local_desktop() {
        assert_eq!(
            browser_opener("linux", vars(&["DISPLAY"])),
            Some("xdg-open")
        );
        assert_eq!(
            browser_opener("linux", vars(&["WAYLAND_DISPLAY"])),
            Some("xdg-open")
        );
        assert_eq!(browser_opener("macos", vars(&[])), Some("open"));

        assert_eq!(browser_opener("linux", vars(&[])), None);
        assert_eq!(
            browser_opener("linux", vars(&["DISPLAY", "SSH_CONNECTION"])),
            None
        );
        assert_eq!(browser_opener("macos", vars(&["SSH_TTY"])), None);
        assert_eq!(browser_opener("windows", vars(&["DISPLAY"])), None);
    }
}
