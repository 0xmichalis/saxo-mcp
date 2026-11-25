//! A GET-only client for the Saxo OpenAPI gateway.
//!
//! This is the only code that talks to the gateway, and it can only send GET
//! requests to paths under the configured gateway URL. It attaches the session's
//! bearer token, replaces a token the gateway rejects once, and follows Saxo's
//! `__next` paging links only while they stay on the gateway.

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::{StatusCode, Url};
use serde_json::Value;

use crate::auth::{AuthError, TokenManager};

const USER_AGENT: &str = concat!("saxo-mcp/", env!("CARGO_PKG_VERSION"));
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// Saxo error messages are short; cap them so a misrouted HTML page cannot
/// flood the tool output.
const MAX_ERROR_MESSAGE: usize = 300;
/// Most pages a paged read fetches, including the first page.
const MAX_PAGES: usize = 20;

/// Errors from a gateway request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SaxoError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    /// The gateway answered with an error.
    #[error("Saxo returned HTTP {status}{}: {message}", code.as_deref().map(|c| format!(" {c}")).unwrap_or_default())]
    Api {
        status: u16,
        code: Option<String>,
        message: String,
    },
    #[error("Saxo rate limit reached{}", retry_after.map(|s| format!("; retry in {s}s")).unwrap_or_default())]
    RateLimited { retry_after: Option<u64> },
    /// The caller's input cannot be sent as asked.
    #[error("{0}")]
    Invalid(String),
    #[error("unexpected Saxo response: {0}")]
    Parse(String),
    #[error("{0}")]
    Transport(String),
}

/// The rows of a paged listing, gathered across pages.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Rows {
    pub rows: Vec<Value>,
    /// The total Saxo reported (`__count`), when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// Whether more rows exist than were fetched.
    pub truncated: bool,
}

/// A GET-only gateway client for one signed-in session.
pub struct SaxoClient {
    http: reqwest::Client,
    gateway: Url,
    tokens: Arc<TokenManager>,
}

impl SaxoClient {
    pub fn new(gateway_url: &str, tokens: Arc<TokenManager>) -> Result<Self, SaxoError> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(HTTP_TIMEOUT)
            // A redirect could carry the bearer token off the gateway.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| SaxoError::Transport(format!("building HTTP client: {e}")))?;
        let gateway = Url::parse(&format!("{}/", gateway_url.trim_end_matches('/')))
            .map_err(|e| SaxoError::Invalid(format!("gateway URL: {e}")))?;
        Ok(Self {
            http,
            gateway,
            tokens,
        })
    }

    pub fn tokens(&self) -> &TokenManager {
        &self.tokens
    }

    /// GET a gateway resource, e.g. `port/v1/balances/me`, and return its JSON.
    /// A `204 No Content` answer is `null`.
    pub async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, SaxoError> {
        let url = self.resource_url(path, query)?;
        self.get_url(&url).await
    }

    /// GET a paged listing (`{"Data": [...], "__next": ...}`) and gather up to
    /// `limit` rows, following `__next` links.
    pub async fn get_rows(
        &self,
        path: &str,
        query: &[(&str, String)],
        limit: usize,
    ) -> Result<Rows, SaxoError> {
        let mut url = self.resource_url(path, query)?;
        let mut visited: Vec<Url> = Vec::new();
        let mut rows = Vec::new();
        let mut total = None;
        let mut truncated = false;
        for page in 1..=MAX_PAGES {
            // All pages stay on the gateway. Only the path and query identify
            // a page there, regardless of spelling of the origin or fragment.
            if visited
                .iter()
                .any(|previous| previous.path() == url.path() && previous.query() == url.query())
            {
                return Err(SaxoError::Parse("paging link repeats a page".to_string()));
            }
            let ListingPage { data, count, next } = ListingPage::parse(self.get_url(&url).await?)?;
            total = total.or(count);
            let remaining = limit - rows.len();
            truncated = data.len() > remaining || next.is_some();
            rows.extend(data.into_iter().take(remaining));

            let Some(next) = next else { break };
            if rows.len() == limit || page == MAX_PAGES {
                break;
            }
            let next = self.next_url(&url, &next)?;
            visited.push(url);
            url = next;
        }
        Ok(Rows {
            rows,
            total,
            truncated,
        })
    }

    fn resource_url(&self, path: &str, query: &[(&str, String)]) -> Result<Url, SaxoError> {
        let mut url = self
            .gateway
            .join(path.trim_start_matches('/'))
            .map_err(|e| SaxoError::Invalid(format!("invalid gateway resource path: {e}")))?;
        if !url.as_str().starts_with(self.gateway.as_str()) {
            return Err(SaxoError::Invalid(
                "resource path leaves the gateway".to_string(),
            ));
        }
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        Ok(url)
    }

    /// Accept a `__next` link only if it points back into the gateway, so the
    /// bearer token never goes anywhere else.
    /// Resolve path links against the gateway. A query-only or fragment-only
    /// link keeps the current resource path.
    fn next_url(&self, current: &Url, next: &str) -> Result<Url, SaxoError> {
        let next = next.trim();
        let base = if next.starts_with(['?', '#']) {
            current
        } else {
            &self.gateway
        };
        let url = base
            .join(next)
            .map_err(|e| SaxoError::Parse(format!("paging link is not a URL: {e}")))?;
        let same_origin = url.origin() == self.gateway.origin();
        if !same_origin || !url.path().starts_with(self.gateway.path()) {
            return Err(SaxoError::Parse(format!(
                "paging link leaves the gateway ({})",
                url.host_str().unwrap_or("no host")
            )));
        }
        Ok(url)
    }

    async fn get_url(&self, url: &Url) -> Result<Value, SaxoError> {
        let token = self.tokens.access_token().await?;
        let response = match self.send(url, &token).await? {
            (StatusCode::UNAUTHORIZED, _, _) => {
                let token = self.tokens.replace_rejected(&token).await?;
                self.send(url, &token).await?
            }
            response => response,
        };
        match response {
            (StatusCode::NO_CONTENT, _, _) => Ok(Value::Null),
            (status, _, body) if status.is_success() => serde_json::from_str(&body).map_err(|e| {
                SaxoError::Parse(format!(
                    "{e} in the response from {}",
                    url.host_str().unwrap_or("the gateway")
                ))
            }),
            (StatusCode::TOO_MANY_REQUESTS, headers, _) => Err(SaxoError::RateLimited {
                retry_after: rate_limit_reset(&headers),
            }),
            (status, _, body) => Err(api_error(status, &body)),
        }
    }

    async fn send(
        &self,
        url: &Url,
        token: &str,
    ) -> Result<(StatusCode, HeaderMap, String), SaxoError> {
        let response = self
            .http
            .get(url.clone())
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| SaxoError::Transport(format!("request failed: {}", e.without_url())))?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await.map_err(|e| {
            SaxoError::Transport(format!("reading response body: {}", e.without_url()))
        })?;
        Ok((status, headers, body))
    }
}

#[derive(Default)]
struct ListingPage {
    data: Vec<Value>,
    count: Option<u64>,
    next: Option<String>,
}

impl ListingPage {
    fn parse(body: Value) -> Result<Self, SaxoError> {
        let mut body = match body {
            Value::Object(body) => body,
            // 204 and some empty listings use null or a bare array.
            Value::Null => return Ok(Self::default()),
            Value::Array(data) => {
                return Ok(Self {
                    data,
                    ..Self::default()
                });
            }
            other => {
                return Err(SaxoError::Parse(format!(
                    "expected a listing object, got {}",
                    json_kind(&other)
                )));
            }
        };
        let data = match body.remove("Data") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(data)) => data,
            Some(_) => {
                return Err(SaxoError::Parse(
                    "listing Data must be an array".to_string(),
                ));
            }
        };
        let next = match body.remove("__next") {
            None | Some(Value::Null) => None,
            Some(Value::String(next)) if next.trim().is_empty() => None,
            Some(Value::String(next)) => Some(next),
            Some(_) => return Err(SaxoError::Parse("paging link must be a string".to_string())),
        };
        let count = body.get("__count").and_then(Value::as_u64);
        Ok(Self { data, count, next })
    }
}

/// Percent-encode `value` for use as one URL path segment. ClientKeys are
/// base64 and can contain `/`, which would otherwise split the segment.
pub fn path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Saxo's error body is `{"ErrorCode", "Message", "ModelState"?}`, on some
/// endpoints wrapped in `{"ErrorInfo": ...}`. Other bodies are shown shortened,
/// except HTML pages (e.g. an Akamai block), which only the status describes.
fn api_error(status: StatusCode, body: &str) -> SaxoError {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ErrorBody {
        error_code: Option<String>,
        message: Option<String>,
        model_state: Option<std::collections::BTreeMap<String, Vec<String>>>,
        error_info: Option<Box<ErrorBody>>,
    }
    let parsed =
        serde_json::from_str::<ErrorBody>(body)
            .ok()
            .map(|mut e| match e.error_info.take() {
                Some(inner) => *inner,
                None => e,
            });
    let (code, message) = match parsed {
        Some(e) if e.error_code.is_some() || e.message.is_some() => {
            let details = e
                .model_state
                .unwrap_or_default()
                .into_iter()
                .map(|(field, problems)| format!("{field}: {}", problems.join("; ")))
                .collect::<Vec<_>>();
            let mut message = e.message.unwrap_or_default();
            if !details.is_empty() {
                message = format!("{message} ({})", details.join(", "));
            }
            (e.error_code, message)
        }
        _ if body.trim_start().starts_with('<') => (None, String::new()),
        _ => (None, body.trim().to_string()),
    };
    let message = match message.trim().is_empty() {
        true => status
            .canonical_reason()
            .unwrap_or("no message")
            .to_string(),
        false => truncate(message.trim(), MAX_ERROR_MESSAGE),
    };
    SaxoError::Api {
        status: status.as_u16(),
        code,
        message,
    }
}

/// The longest `X-RateLimit-*-Reset` wait, in seconds.
fn rate_limit_reset(headers: &HeaderMap) -> Option<u64> {
    headers
        .iter()
        .filter(|(name, _)| {
            let name = name.as_str();
            name.starts_with("x-ratelimit-") && name.ends_with("-reset")
        })
        .filter_map(|(_, value)| value.to_str().ok()?.trim().parse::<u64>().ok())
        .max()
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    match text.char_indices().nth(max_chars) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;
    use serde_json::json;

    use super::*;

    #[test]
    fn listing_pages_accept_empty_and_bare_array_responses() {
        for body in [
            Value::Null,
            json!({}),
            json!({"Data": null, "__next": null}),
            json!({"Data": [], "__next": ""}),
        ] {
            let page = ListingPage::parse(body).unwrap();
            assert!(page.data.is_empty());
            assert_eq!(page.next, None);
        }
        let page = ListingPage::parse(json!([{"OrderId": "1"}])).unwrap();
        assert_eq!(page.data, [json!({"OrderId": "1"})]);
    }

    #[test]
    fn api_errors_use_saxo_fields_or_a_short_body() {
        let err = api_error(
            StatusCode::BAD_REQUEST,
            r#"{"ErrorCode":"InvalidRequest","Message":"Bad FieldGroups"}"#,
        );
        assert_eq!(
            err.to_string(),
            "Saxo returned HTTP 400 InvalidRequest: Bad FieldGroups"
        );
        let err = api_error(StatusCode::BAD_GATEWAY, &"x".repeat(1000));
        assert_eq!(
            err.to_string().chars().count(),
            "Saxo returned HTTP 502: ".len() + 301
        );
        let err = api_error(StatusCode::NOT_FOUND, "");
        assert_eq!(err.to_string(), "Saxo returned HTTP 404: Not Found");
        let err = api_error(
            StatusCode::FORBIDDEN,
            "<html><body>Access Denied</body></html>",
        );
        assert_eq!(err.to_string(), "Saxo returned HTTP 403: Forbidden");
    }

    #[test]
    fn api_errors_unwrap_error_info_and_list_model_state() {
        let err = api_error(
            StatusCode::BAD_REQUEST,
            r#"{"ErrorInfo":{"ErrorCode":"IllegalAmount","Message":"Amount too small"}}"#,
        );
        assert_eq!(
            err.to_string(),
            "Saxo returned HTTP 400 IllegalAmount: Amount too small"
        );
        let err = api_error(
            StatusCode::BAD_REQUEST,
            r#"{"ErrorCode":"InvalidModelState","Message":"One or more properties of the request are invalid!","ModelState":{"$skip":["Invalid $skip query parameter value: 2s"]}}"#,
        );
        assert_eq!(
            err.to_string(),
            "Saxo returned HTTP 400 InvalidModelState: One or more properties of the request \
             are invalid! ($skip: Invalid $skip query parameter value: 2s)"
        );
    }

    #[test]
    fn path_segments_escape_separators() {
        assert_eq!(path_segment("Ab0-._~"), "Ab0-._~");
        assert_eq!(path_segment("a/b+c=="), "a%2Fb%2Bc%3D%3D");
        assert_eq!(path_segment("../x"), "..%2Fx");
    }

    #[test]
    fn rate_limit_reset_takes_the_longest_wait() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-session-reset", HeaderValue::from_static("12"));
        headers.insert("x-ratelimit-appday-reset", HeaderValue::from_static("3600"));
        headers.insert(
            "x-ratelimit-session-remaining",
            HeaderValue::from_static("0"),
        );
        assert_eq!(rate_limit_reset(&headers), Some(3600));
        assert_eq!(rate_limit_reset(&HeaderMap::new()), None);
    }
}
