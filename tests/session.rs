//! Session handling against local stand-ins for Saxo's token endpoint and
//! gateway: refresh and rotation, the shared token file, 401 recovery, paging,
//! and that credentials never surface in errors.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use reqwest::Url;
use saxo_mcp::auth::store::{self, TokenSet};
use saxo_mcp::auth::{AuthError, TokenManager, unix_now};
use saxo_mcp::config::{Config, Environment};
use saxo_mcp::saxo::{SaxoClient, SaxoError};
use serde_json::json;
use wiremock::matchers::{body_string_contains, header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const APP_KEY: &str = "test-app";

fn temp_token_file(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("saxo-mcp-session-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("sim-tokens.json")
}

fn config(server: &MockServer, token_file: &Path, app_secret: Option<&str>) -> Config {
    Config {
        env: Environment::Sim,
        app_key: APP_KEY.to_string(),
        app_secret: app_secret.map(str::to_string),
        redirect_uri: Url::parse("http://localhost:8765/callback").unwrap(),
        token_file: token_file.to_path_buf(),
        gateway_url: format!("{}/sim/openapi", server.uri()),
        auth_url: server.uri(),
    }
}

fn tokens(access: &str, access_ttl: i64, refresh: &str) -> TokenSet {
    TokenSet {
        env: Environment::Sim,
        app_key: APP_KEY.to_string(),
        access_token: access.to_string(),
        access_expires_at: (unix_now() as i64 + access_ttl) as u64,
        refresh_token: refresh.to_string(),
        refresh_expires_at: Some(unix_now() + 3600),
        code_verifier: Some("verifier".to_string()),
    }
}

fn token_response(access: &str, refresh: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": 1200,
        "refresh_token": refresh,
        "refresh_token_expires_in": 3600,
    }))
}

fn client(config: &Config) -> SaxoClient {
    let tokens = Arc::new(TokenManager::new(config).unwrap());
    SaxoClient::new(&config.gateway_url, tokens).unwrap()
}

#[tokio::test]
async fn signed_out_errors_point_at_the_auth_command() {
    let server = MockServer::start().await;
    let file = temp_token_file("signed-out");
    let manager = TokenManager::new(&config(&server, &file, None)).unwrap();

    let err = manager.access_token().await.unwrap_err();

    assert!(err.needs_login());
    assert!(matches!(err, AuthError::NotSignedIn { .. }));
    assert!(err.to_string().contains("saxo-mcp auth"), "{err}");
}

#[tokio::test]
async fn a_valid_stored_token_is_sent_as_bearer_without_refreshing() {
    let server = MockServer::start().await;
    let file = temp_token_file("valid");
    store::save(&file, &tokens("access-1", 600, "refresh-1")).unwrap();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sim/openapi/port/v1/users/me"))
        .and(header("authorization", "Bearer access-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "Name": "Test" })))
        .expect(1)
        .mount(&server)
        .await;

    let body = client(&config(&server, &file, None))
        .get("port/v1/users/me", &[])
        .await
        .unwrap();

    assert_eq!(body, json!({ "Name": "Test" }));
}

#[tokio::test]
async fn an_expiring_token_is_refreshed_and_the_rotation_saved() {
    let server = MockServer::start().await;
    let file = temp_token_file("refresh");
    store::save(&file, &tokens("old-access", 30, "old-refresh")).unwrap();
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=old-refresh"))
        .and(body_string_contains("client_id=test-app"))
        .and(body_string_contains("code_verifier=verifier"))
        .and(body_string_contains(
            "redirect_uri=http%3A%2F%2Flocalhost%3A8765%2Fcallback",
        ))
        .respond_with(token_response("new-access", "new-refresh"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(header("authorization", "Bearer new-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;

    client(&config(&server, &file, None))
        .get("port/v1/users/me", &[])
        .await
        .unwrap();

    let saved = store::load(&file).unwrap().unwrap();
    assert_eq!(saved.access_token, "new-access");
    assert_eq!(saved.refresh_token, "new-refresh");
    assert!(saved.access_expires_at >= unix_now() + 1190);
}

#[tokio::test]
async fn apps_with_a_secret_authenticate_with_basic_auth() {
    let server = MockServer::start().await;
    let file = temp_token_file("secret");
    store::save(&file, &tokens("old-access", 0, "old-refresh")).unwrap();
    Mock::given(method("POST"))
        .and(path("/token"))
        // base64("test-app:s3cret")
        .and(header("authorization", "Basic dGVzdC1hcHA6czNjcmV0"))
        .respond_with(token_response("new-access", "new-refresh"))
        .expect(1)
        .mount(&server)
        .await;

    let manager = TokenManager::new(&config(&server, &file, Some("s3cret"))).unwrap();
    assert_eq!(manager.access_token().await.unwrap(), "new-access");
}

#[tokio::test]
async fn processes_sharing_the_file_refresh_once() {
    let server = MockServer::start().await;
    let file = temp_token_file("shared");
    store::save(&file, &tokens("old-access", 0, "old-refresh")).unwrap();
    // A second refresh would present the rotated-away token; Saxo would end the
    // session, so it must not happen.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            token_response("new-access", "new-refresh")
                .set_delay(std::time::Duration::from_millis(200)),
        )
        .expect(1)
        .mount(&server)
        .await;

    // Two managers stand in for two server processes (e.g. two Hermes profiles).
    let config = config(&server, &file, None);
    let first = TokenManager::new(&config).unwrap();
    let second = TokenManager::new(&config).unwrap();
    let (a, b) = tokio::join!(first.access_token(), second.access_token());

    assert_eq!(a.unwrap(), "new-access");
    assert_eq!(b.unwrap(), "new-access");
}

#[tokio::test]
async fn a_refused_refresh_ends_the_session_without_leaking_tokens() {
    let server = MockServer::start().await;
    let file = temp_token_file("refused");
    store::save(&file, &tokens("ACCESS-SENTINEL", 0, "REFRESH-SENTINEL")).unwrap();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "refresh token REFRESH-SENTINEL is no longer valid",
        })))
        .mount(&server)
        .await;

    let err = client(&config(&server, &file, Some("SECRET-SENTINEL")))
        .get("port/v1/users/me", &[])
        .await
        .unwrap_err();

    let SaxoError::Auth(auth) = &err else {
        panic!("expected an auth error, got {err:?}");
    };
    assert!(auth.needs_login());
    let shown = format!("{err} {err:?}");
    assert!(shown.contains("invalid_grant"), "{shown}");
    assert!(shown.contains("saxo-mcp auth"), "{shown}");
    assert!(!shown.contains("SENTINEL"), "{shown}");
}

#[tokio::test]
async fn an_expired_refresh_token_is_not_sent() {
    let server = MockServer::start().await;
    let file = temp_token_file("expired-refresh");
    let mut stale = tokens("access", 0, "refresh");
    stale.refresh_expires_at = Some(unix_now() - 1);
    store::save(&file, &stale).unwrap();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let manager = TokenManager::new(&config(&server, &file, None)).unwrap();
    let err = manager.access_token().await.unwrap_err();
    assert!(err.needs_login(), "{err}");
}

#[tokio::test]
async fn tokens_of_another_app_are_refused() {
    let server = MockServer::start().await;
    let file = temp_token_file("other-app");
    let mut foreign = tokens("access", 600, "refresh");
    foreign.app_key = "someone-else".to_string();
    store::save(&file, &foreign).unwrap();

    let manager = TokenManager::new(&config(&server, &file, None)).unwrap();
    let err = manager.access_token().await.unwrap_err();
    assert!(matches!(err, AuthError::WrongSession(_)), "{err}");
}

#[tokio::test]
async fn a_rejected_token_is_replaced_once() {
    let server = MockServer::start().await;
    let file = temp_token_file("rejected");
    store::save(&file, &tokens("revoked-access", 600, "refresh-1")).unwrap();
    Mock::given(method("GET"))
        .and(header("authorization", "Bearer revoked-access"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=refresh-1"))
        .respond_with(token_response("fresh-access", "refresh-2"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(header("authorization", "Bearer fresh-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .expect(1)
        .mount(&server)
        .await;

    let body = client(&config(&server, &file, None))
        .get("port/v1/users/me", &[])
        .await
        .unwrap();
    assert_eq!(body, json!({ "ok": true }));
}

#[tokio::test]
async fn a_second_rejection_is_reported_not_retried() {
    let server = MockServer::start().await;
    let file = temp_token_file("rejected-twice");
    store::save(&file, &tokens("access-1", 600, "refresh-1")).unwrap();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(token_response("access-2", "refresh-2"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .expect(2)
        .mount(&server)
        .await;

    let err = client(&config(&server, &file, None))
        .get("port/v1/users/me", &[])
        .await
        .unwrap_err();
    assert!(matches!(err, SaxoError::Api { status: 401, .. }), "{err:?}");
}

#[tokio::test]
async fn rate_limits_report_the_wait() {
    let server = MockServer::start().await;
    let file = temp_token_file("rate-limit");
    store::save(&file, &tokens("access", 600, "refresh")).unwrap();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("X-RateLimit-Session-Reset", "42"))
        .mount(&server)
        .await;

    let err = client(&config(&server, &file, None))
        .get("port/v1/balances/me", &[])
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "Saxo rate limit reached; retry in 42s");
}

#[tokio::test]
async fn paging_follows_next_links_up_to_the_limit() {
    let server = MockServer::start().await;
    let file = temp_token_file("paging");
    store::save(&file, &tokens("access", 600, "refresh")).unwrap();
    let base = format!("{}/sim/openapi", server.uri());
    Mock::given(method("GET"))
        .and(path("/sim/openapi/port/v1/orders/me"))
        .and(wiremock::matchers::query_param_is_missing("$skip"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "__count": 5,
            // Saxo also sends root-relative links.
            "__next": "/sim/openapi/port/v1/orders/me?$skip=2&$top=2",
            "Data": [{ "OrderId": "1" }, { "OrderId": "2" }],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sim/openapi/port/v1/orders/me"))
        .and(wiremock::matchers::query_param("$skip", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "__count": 5,
            "__next": format!("{base}/port/v1/orders/me?$skip=4&$top=2"),
            "Data": [{ "OrderId": "3" }, { "OrderId": "4" }],
        })))
        .mount(&server)
        .await;

    let rows = client(&config(&server, &file, None))
        .get_rows("port/v1/orders/me", &[], 3)
        .await
        .unwrap();

    let ids: Vec<_> = rows.rows.iter().map(|r| r["OrderId"].clone()).collect();
    assert_eq!(ids, [json!("1"), json!("2"), json!("3")]);
    assert_eq!(rows.total, Some(5));
    assert!(rows.truncated);
}

#[tokio::test]
async fn paging_links_off_the_gateway_are_refused() {
    let gateway = MockServer::start().await;
    let elsewhere = MockServer::start().await;
    let file = temp_token_file("foreign-next");
    store::save(&file, &tokens("access", 600, "refresh")).unwrap();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "__next": format!("{}/sim/openapi/port/v1/orders/me?$skip=1", elsewhere.uri()),
            "Data": [{ "OrderId": "1" }],
        })))
        .mount(&gateway)
        .await;
    Mock::given(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&elsewhere)
        .await;

    let err = client(&config(&gateway, &file, None))
        .get_rows("port/v1/orders/me", &[], 10)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("paging link leaves the gateway"),
        "{err}"
    );
}

#[tokio::test]
async fn resource_paths_cannot_climb_out_of_the_gateway() {
    let server = MockServer::start().await;
    let file = temp_token_file("climb");
    store::save(&file, &tokens("access", 600, "refresh")).unwrap();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(0)
        .mount(&server)
        .await;

    let err = client(&config(&server, &file, None))
        .get("../../token", &[])
        .await
        .unwrap_err();
    assert!(matches!(err, SaxoError::Invalid(_)), "{err:?}");
}

#[tokio::test]
async fn saxos_bare_bad_request_page_ends_the_session() {
    let server = MockServer::start().await;
    let file = temp_token_file("html-400");
    store::save(&file, &tokens("access", 0, "rotated-away")).unwrap();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(400).set_body_raw("Bad Request", "text/html; charset=us-ascii"),
        )
        .mount(&server)
        .await;

    let manager = TokenManager::new(&config(&server, &file, None)).unwrap();
    let err = manager.access_token().await.unwrap_err();

    assert!(err.needs_login(), "{err}");
    assert_eq!(
        err.to_string(),
        "the Saxo session has ended (HTTP 400 Bad Request); sign in again with `saxo-mcp auth`"
    );
}

#[tokio::test]
async fn a_negative_lifetime_yields_an_already_expired_token() {
    let server = MockServer::start().await;
    let file = temp_token_file("negative");
    store::save(&file, &tokens("access", 0, "refresh")).unwrap();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "late",
            "expires_in": -5,
            "refresh_token": "refresh-2",
        })))
        .mount(&server)
        .await;

    let manager = TokenManager::new(&config(&server, &file, None)).unwrap();
    // The refreshed token is handed out once; it is saved as expired, so the
    // next call refreshes again rather than trusting it.
    assert_eq!(manager.access_token().await.unwrap(), "late");
    let saved = store::load(&file).unwrap().unwrap();
    assert!(saved.access_expires_at < unix_now());
    assert_eq!(saved.refresh_expires_at, None);
    assert_eq!(saved.code_verifier.as_deref(), Some("verifier"));
}

#[tokio::test]
async fn a_refused_refresh_token_is_not_sent_again_until_a_new_login() {
    let server = MockServer::start().await;
    let file = temp_token_file("refused-once");
    store::save(&file, &tokens("access", 0, "dead-refresh")).unwrap();
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=dead-refresh"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=new-login-refresh"))
        .respond_with(token_response("after-login", "refresh-3"))
        .expect(1)
        .mount(&server)
        .await;

    let manager = TokenManager::new(&config(&server, &file, None)).unwrap();
    for _ in 0..3 {
        assert!(manager.access_token().await.unwrap_err().needs_login());
    }

    // `saxo-mcp auth` in another process writes a new session.
    store::save(&file, &tokens("expired", 0, "new-login-refresh")).unwrap();
    assert_eq!(manager.access_token().await.unwrap(), "after-login");
}

#[tokio::test]
async fn keep_alive_refreshes_ahead_of_expiry() {
    let server = MockServer::start().await;
    let file = temp_token_file("keep-alive");
    store::save(&file, &tokens("first", 0, "refresh-1")).unwrap();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(token_response("next", "refresh-n"))
        .mount(&server)
        .await;

    let manager = std::sync::Arc::new(TokenManager::new(&config(&server, &file, None)).unwrap());
    let task = tokio::spawn({
        let manager = manager.clone();
        async move { manager.keep_alive().await }
    });
    // The stored access token is already inside the lead time, so the first
    // pass refreshes it straight away.
    for _ in 0..100 {
        if store::load(&file).unwrap().unwrap().access_token == "next" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    task.abort();

    assert_eq!(
        store::load(&file).unwrap().unwrap().refresh_token,
        "refresh-n"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
