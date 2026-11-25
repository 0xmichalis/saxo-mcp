//! The MCP tools end to end: an MCP client over an in-memory pipe, the server,
//! and a local stand-in for the Saxo gateway. Checks which Saxo resources each
//! tool reads, with which parameters, and what it hands back.

use std::path::PathBuf;
use std::sync::Arc;

use reqwest::Url;
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use saxo_mcp::auth::TokenManager;
use saxo_mcp::auth::store::{self, TokenSet};
use saxo_mcp::auth::unix_now;
use saxo_mcp::config::{Config, Environment};
use saxo_mcp::mcp::SaxoServer;
use saxo_mcp::saxo::SaxoClient;
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CLIENT_KEY: &str = "Ck/9+x==";

struct Harness {
    gateway: MockServer,
    client: RunningService<RoleClient, ()>,
    token_file: PathBuf,
}

/// A signed-in session with the given access token, valid for 20 minutes.
fn session(access: &str) -> TokenSet {
    TokenSet {
        env: Environment::Sim,
        app_key: "app".to_string(),
        access_token: access.to_string(),
        access_expires_at: unix_now() + 1200,
        refresh_token: format!("{access}-refresh"),
        refresh_expires_at: Some(unix_now() + 3600),
        code_verifier: None,
    }
}

impl Harness {
    async fn start(name: &str) -> Self {
        let gateway = MockServer::start().await;
        let dir =
            std::env::temp_dir().join(format!("saxo-mcp-tools-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let token_file = dir.join("sim-tokens.json");
        store::save(&token_file, &session("access")).unwrap();
        let config = Config {
            env: Environment::Sim,
            app_key: "app".to_string(),
            app_secret: None,
            redirect_uri: Url::parse("http://localhost:8765/callback").unwrap(),
            token_file: token_file.clone(),
            gateway_url: format!("{}/sim/openapi", gateway.uri()),
            auth_url: gateway.uri(),
        };
        let tokens = Arc::new(TokenManager::new(&config).unwrap());
        let server = SaxoServer::new(
            SaxoClient::new(&config.gateway_url, tokens).unwrap(),
            Environment::Sim,
        );

        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            if let Ok(running) = server.serve(server_io).await {
                let _ = running.waiting().await;
            }
        });
        let client = ().serve(client_io).await.unwrap();
        Self {
            gateway,
            client,
            token_file,
        }
    }

    async fn mock(&self, resource: &str, body: Value) {
        Mock::given(method("GET"))
            .and(path(format!("/sim/openapi/{resource}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&self.gateway)
            .await;
    }

    async fn mock_client_key(&self) {
        self.mock("port/v1/clients/me", json!({ "ClientKey": CLIENT_KEY }))
            .await;
    }

    async fn call(&self, tool: &'static str, args: Value) -> CallToolResult {
        let params = CallToolRequestParams::new(tool)
            .with_arguments(args.as_object().cloned().unwrap_or_default());
        self.client.call_tool(params).await.unwrap()
    }
}

fn structured(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "tool failed: {result:?}");
    result
        .structured_content
        .clone()
        .expect("structured content")
}

fn error_text(result: &CallToolResult) -> String {
    assert_eq!(
        result.is_error,
        Some(true),
        "expected a tool error: {result:?}"
    );
    serde_json::to_string(&result.content).unwrap()
}

#[tokio::test]
async fn lists_only_read_only_tools() {
    let h = Harness::start("list").await;
    let tools = h.client.list_all_tools().await.unwrap();

    let mut names: Vec<_> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "saxo_accounts",
            "saxo_balances",
            "saxo_closed_positions",
            "saxo_instrument_details",
            "saxo_instrument_search",
            "saxo_orders",
            "saxo_performance",
            "saxo_performance_summary",
            "saxo_positions",
            "saxo_prices",
            "saxo_session",
            "saxo_transactions",
        ]
    );
    for tool in &tools {
        let read_only = tool.annotations.as_ref().and_then(|a| a.read_only_hint);
        assert_eq!(read_only, Some(true), "{} must be read-only", tool.name);
    }
}

#[tokio::test]
async fn session_reports_expiry_and_who_is_signed_in() {
    let h = Harness::start("session").await;
    h.mock("port/v1/users/me", json!({ "Name": "Test User" }))
        .await;
    h.mock_client_key().await;

    let out = structured(&h.call("saxo_session", json!({})).await);

    assert_eq!(out["session"]["env"], "sim");
    assert!(out["session"]["access_expires_at"].as_u64().unwrap() > unix_now());
    assert_eq!(out["user"]["Name"], "Test User");
    assert_eq!(out["client"]["ClientKey"], CLIENT_KEY);
    let text = serde_json::to_string(&out).unwrap();
    assert!(
        !text.contains("\"access\""),
        "tokens must not appear: {text}"
    );
}

#[tokio::test]
async fn accounts_are_listed() {
    let h = Harness::start("accounts").await;
    h.mock(
        "port/v1/accounts/me",
        json!({ "Data": [{ "AccountKey": "ak1", "AccountId": "123", "Currency": "EUR" }] }),
    )
    .await;

    let out = structured(&h.call("saxo_accounts", json!({})).await);

    assert_eq!(out["accounts"][0]["AccountKey"], "ak1");
    assert_eq!(out["truncated"], false);
}

#[tokio::test]
async fn balances_cover_the_client_or_one_account() {
    let h = Harness::start("balances").await;
    h.mock("port/v1/balances/me", json!({ "TotalValue": 1000.5 }))
        .await;
    h.mock_client_key().await;
    Mock::given(method("GET"))
        .and(path("/sim/openapi/port/v1/balances"))
        .and(query_param("ClientKey", CLIENT_KEY))
        .and(query_param("AccountKey", "ak1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "TotalValue": 10 })))
        .mount(&h.gateway)
        .await;

    let all = structured(&h.call("saxo_balances", json!({})).await);
    let one = structured(
        &h.call("saxo_balances", json!({ "account_key": "ak1" }))
            .await,
    );

    assert_eq!(all["TotalValue"], 1000.5);
    assert_eq!(one["TotalValue"], 10);
}

#[tokio::test]
async fn positions_read_the_requested_view_with_display_fields() {
    let h = Harness::start("positions").await;
    for (resource, groups) in [
        (
            "port/v1/netpositions/me",
            "NetPositionBase,NetPositionView,DisplayAndFormat,ExchangeInfo",
        ),
        (
            "port/v1/positions/me",
            "PositionBase,PositionView,Costs,DisplayAndFormat,ExchangeInfo",
        ),
        (
            "port/v1/closedpositions/me",
            "ClosedPosition,DisplayAndFormat,ExchangeInfo",
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/sim/openapi/{resource}")))
            .and(query_param("FieldGroups", groups))
            .and(query_param("$top", "200"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "Data": [{ "From": resource }] })),
            )
            .mount(&h.gateway)
            .await;
    }

    let net = structured(&h.call("saxo_positions", json!({})).await);
    let open = structured(&h.call("saxo_positions", json!({ "view": "open" })).await);
    let closed = structured(&h.call("saxo_positions", json!({ "view": "closed" })).await);

    assert_eq!(net["positions"][0]["From"], "port/v1/netpositions/me");
    assert_eq!(open["positions"][0]["From"], "port/v1/positions/me");
    assert_eq!(closed["positions"][0]["From"], "port/v1/closedpositions/me");
}

#[tokio::test]
async fn account_scoped_listings_pass_client_and_account_keys() {
    let h = Harness::start("orders").await;
    h.mock_client_key().await;
    Mock::given(method("GET"))
        .and(path("/sim/openapi/port/v1/orders"))
        .and(query_param("ClientKey", CLIENT_KEY))
        .and(query_param("AccountKey", "ak1"))
        .and(query_param("$top", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "__count": 1,
            "Data": [{ "OrderId": "42" }],
        })))
        .mount(&h.gateway)
        .await;

    let out = structured(
        &h.call("saxo_orders", json!({ "account_key": "ak1", "limit": 5 }))
            .await,
    );

    assert_eq!(
        out,
        json!({ "orders": [{ "OrderId": "42" }], "total": 1, "truncated": false })
    );
}

#[tokio::test]
async fn instrument_search_and_details() {
    let h = Harness::start("instruments").await;
    Mock::given(method("GET"))
        .and(path("/sim/openapi/ref/v1/instruments"))
        .and(query_param("Keywords", "apple"))
        .and(query_param("AssetTypes", "Stock,Etf"))
        .and(query_param("$top", "25"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Data": [{ "Identifier": 211, "AssetType": "Stock", "Symbol": "AAPL:xnas" }],
        })))
        .mount(&h.gateway)
        .await;
    h.mock(
        "ref/v1/instruments/details/211/Stock",
        json!({ "Uic": 211, "CurrencyCode": "USD" }),
    )
    .await;

    let found = structured(
        &h.call(
            "saxo_instrument_search",
            json!({ "keywords": " apple ", "asset_types": ["Stock", "Etf"] }),
        )
        .await,
    );
    let details = structured(
        &h.call(
            "saxo_instrument_details",
            json!({ "uic": 211, "asset_type": "Stock" }),
        )
        .await,
    );

    assert_eq!(found["instruments"][0]["Symbol"], "AAPL:xnas");
    assert_eq!(details["CurrencyCode"], "USD");
}

#[tokio::test]
async fn prices_batch_uics_of_one_asset_type() {
    let h = Harness::start("prices").await;
    Mock::given(method("GET"))
        .and(path("/sim/openapi/trade/v1/infoprices/list"))
        .and(query_param("Uics", "211,212"))
        .and(query_param("AssetType", "Stock"))
        .and(query_param_is_missing("$top"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Data": [{ "Uic": 211, "Quote": { "Bid": 1.0 } }, { "Uic": 212 }],
        })))
        .mount(&h.gateway)
        .await;

    let out = structured(
        &h.call(
            "saxo_prices",
            json!({ "uics": [212, 211, 212], "asset_type": "Stock" }),
        )
        .await,
    );

    assert_eq!(out["prices"][0]["Quote"]["Bid"], 1.0);
    assert_eq!(out["prices"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn bad_input_is_refused_before_reaching_saxo() {
    let h = Harness::start("bad-input").await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(0)
        .mount(&h.gateway)
        .await;

    let traversal = h
        .call(
            "saxo_instrument_details",
            json!({ "uic": 1, "asset_type": "../../port/v1/users/me" }),
        )
        .await;
    let no_uics = h
        .call("saxo_prices", json!({ "uics": [], "asset_type": "Stock" }))
        .await;
    let blank = h
        .call("saxo_instrument_search", json!({ "keywords": "  " }))
        .await;
    let bad_type = h
        .call(
            "saxo_transactions",
            json!({ "from_date": "2024-02-29", "asset_types": ["Fx Spot"] }),
        )
        .await;
    let bad_date = h
        .call("saxo_performance", json!({ "from_date": "2025-02-29" }))
        .await;
    let bad_field_group = h
        .call(
            "saxo_performance_summary",
            json!({ "field_groups": ["All&MockDataId=002"] }),
        )
        .await;

    assert!(error_text(&traversal).contains("asset type must be"));
    assert!(error_text(&no_uics).contains("between 1 and 50"));
    assert!(error_text(&blank).contains("keywords must not be empty"));
    assert!(error_text(&bad_type).contains("asset type must be"));
    assert!(error_text(&bad_date).contains("YYYY-MM-DD"));
    assert!(error_text(&bad_field_group).contains("unknown field group"));
}

#[tokio::test]
async fn saxo_errors_reach_the_model_as_tool_errors() {
    let h = Harness::start("api-error").await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "ErrorCode": "InvalidModelState",
            "Message": "Unknown FieldGroups",
        })))
        .mount(&h.gateway)
        .await;

    let result = h.call("saxo_accounts", json!({})).await;

    let text = error_text(&result);
    assert!(
        text.contains("HTTP 400 InvalidModelState: Unknown FieldGroups"),
        "{text}"
    );
}

#[tokio::test]
async fn transactions_cover_a_date_range_with_filters() {
    let h = Harness::start("transactions").await;
    h.mock_client_key().await;
    Mock::given(method("GET"))
        .and(path("/sim/openapi/hist/v1/transactions"))
        .and(query_param("ClientKey", CLIENT_KEY))
        .and(query_param("FromDate", "2026-01-01"))
        .and(query_param("ToDate", "2026-03-31"))
        .and(query_param("AccountKeys", "ak1,ak2"))
        .and(query_param("TransactionType", "Trade"))
        .and(query_param("AssetTypes", "Stock,Etf"))
        .and(query_param("Uics", "211,212"))
        .and(query_param("$top", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Data": [{ "TradeId": "1", "TotalCost": -21.12, "ConversionCost": -0.11 }],
        })))
        .expect(1)
        .mount(&h.gateway)
        .await;

    let out = structured(
        &h.call(
            "saxo_transactions",
            json!({
                "from_date": "2026-01-01",
                "to_date": "2026-03-31",
                "account_keys": ["ak1", "ak2"],
                "transaction_type": "Trade",
                "asset_types": ["Stock", "Etf"],
                "uics": [211, 212],
                "limit": 50,
            }),
        )
        .await,
    );

    assert_eq!(out["transactions"][0]["TotalCost"], -21.12);
}

#[tokio::test]
async fn transactions_end_today_by_default_and_reject_bad_ranges() {
    let h = Harness::start("transactions-default").await;
    h.mock_client_key().await;
    Mock::given(method("GET"))
        .and(path("/sim/openapi/hist/v1/transactions"))
        .and(query_param("FromDate", "2026-01-01"))
        .and(wiremock::matchers::query_param_contains("ToDate", "-"))
        .and(query_param("$top", "200"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "Data": [] })))
        .expect(1)
        .mount(&h.gateway)
        .await;

    structured(
        &h.call("saxo_transactions", json!({ "from_date": "2026-01-01" }))
            .await,
    );
    let reversed = h
        .call(
            "saxo_transactions",
            json!({ "from_date": "2026-02-01", "to_date": "2026-01-01" }),
        )
        .await;
    let malformed = h
        .call("saxo_transactions", json!({ "from_date": "01/02/2026" }))
        .await;

    assert!(error_text(&reversed).contains("is after to_date"));
    assert!(error_text(&malformed).contains("YYYY-MM-DD"));
}

#[tokio::test]
async fn closed_positions_put_the_escaped_client_key_and_dates_in_the_path() {
    let h = Harness::start("closed").await;
    h.mock_client_key().await;
    Mock::given(method("GET"))
        .and(path(
            "/sim/openapi/cs/v1/reports/closedPositions/Ck%2F9%2Bx%3D%3D/2026-01-01/2026-06-30",
        ))
        .and(query_param("AccountKey", "ak1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Data": [{ "ClosedProfitLoss": 12.5 }],
        })))
        .expect(1)
        .mount(&h.gateway)
        .await;

    let out = structured(
        &h.call(
            "saxo_closed_positions",
            json!({ "from_date": "2026-01-01", "to_date": "2026-06-30", "account_key": "ak1" }),
        )
        .await,
    );

    assert_eq!(out["closed_positions"][0]["ClosedProfitLoss"], 12.5);
}

#[tokio::test]
async fn performance_defaults_to_a_year_and_asks_sim_for_mock_data() {
    let h = Harness::start("performance").await;
    h.mock_client_key().await;
    Mock::given(method("GET"))
        .and(path("/sim/openapi/hist/v4/performance/timeseries"))
        .and(query_param("ClientKey", CLIENT_KEY))
        .and(query_param("StandardPeriod", "Year"))
        .and(query_param(
            "FieldGroups",
            "Balance_AccountValue,Balance_CashTransfer,TimeWeighted_Accumulated,KeyFigures",
        ))
        .and(query_param("MockDataId", "001"))
        .and(query_param_is_missing("FromDate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Balance": { "AccountValue": [{ "Date": "2026-05-09", "Value": 584.38 }] },
        })))
        .expect(1)
        .mount(&h.gateway)
        .await;

    let out = structured(&h.call("saxo_performance", json!({})).await);

    assert_eq!(out["Balance"]["AccountValue"][0]["Value"], 584.38);
}

#[tokio::test]
async fn performance_summary_takes_dates_account_and_field_groups() {
    let h = Harness::start("summary").await;
    h.mock_client_key().await;
    Mock::given(method("GET"))
        .and(path("/sim/openapi/hist/v4/performance/summary"))
        .and(query_param("FromDate", "2025-01-01"))
        .and(query_param("ToDate", "2025-12-31"))
        .and(query_param("AccountKey", "ak1"))
        .and(query_param("FieldGroups", "Allocation,TradeActivity"))
        .and(query_param_is_missing("StandardPeriod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "Allocation": {} })))
        .expect(1)
        .mount(&h.gateway)
        .await;

    let out = structured(
        &h.call(
            "saxo_performance_summary",
            json!({
                "period": "AllTime",
                "from_date": "2025-01-01",
                "to_date": "2025-12-31",
                "account_key": "ak1",
                "field_groups": ["Allocation", "TradeActivity"],
            }),
        )
        .await,
    );
    let bad = h
        .call(
            "saxo_performance_summary",
            json!({ "field_groups": ["All&MockDataId=002"] }),
        )
        .await;

    assert_eq!(out, json!({ "Allocation": {} }));
    assert!(error_text(&bad).contains("unknown field group"));
}

#[tokio::test]
async fn a_new_login_for_another_client_gets_its_own_client_key() {
    let h = Harness::start("switch-client").await;
    for (bearer, key) in [("access", CLIENT_KEY), ("second", "Second/Key")] {
        Mock::given(method("GET"))
            .and(path("/sim/openapi/port/v1/clients/me"))
            .and(header("authorization", format!("Bearer {bearer}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ClientKey": key })))
            .expect(1)
            .mount(&h.gateway)
            .await;
        Mock::given(method("GET"))
            .and(path("/sim/openapi/hist/v1/transactions"))
            .and(header("authorization", format!("Bearer {bearer}")))
            .and(query_param("ClientKey", key))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "Data": [{ "TransactionId": bearer }] })),
            )
            .expect(1)
            .mount(&h.gateway)
            .await;
    }
    let range = json!({ "from_date": "2026-01-01", "to_date": "2026-01-31" });
    let first = structured(&h.call("saxo_transactions", range.clone()).await);
    assert_eq!(first["transactions"][0]["TransactionId"], "access");

    // Another client signs in with `saxo-mcp auth`, and Saxo stops accepting
    // the old session's token.
    store::save(&h.token_file, &session("second")).unwrap();
    Mock::given(header("authorization", "Bearer access"))
        .respond_with(ResponseTemplate::new(401))
        .with_priority(1)
        .mount(&h.gateway)
        .await;
    h.mock("port/v1/accounts/me", json!({ "Data": [] })).await;
    structured(&h.call("saxo_accounts", json!({})).await);

    let second = structured(&h.call("saxo_transactions", range).await);
    assert_eq!(second["transactions"][0]["TransactionId"], "second");
}

#[tokio::test]
async fn a_bare_array_listing_is_read_as_rows() {
    let h = Harness::start("bare-array").await;
    // What the SIM gateway answers for an account that has closed nothing.
    h.mock("port/v1/closedpositions/me", json!([])).await;

    let out = structured(&h.call("saxo_positions", json!({ "view": "closed" })).await);

    assert_eq!(out, json!({ "positions": [], "truncated": false }));
}

#[tokio::test]
async fn malformed_listings_are_tool_errors() {
    let h = Harness::start("malformed-listings").await;
    h.mock("port/v1/accounts/me", json!({ "Data": {} })).await;
    h.mock("port/v1/orders/me", json!({ "Data": [], "__next": 42 }))
        .await;

    let bad_data = h.call("saxo_accounts", json!({})).await;
    let bad_next = h.call("saxo_orders", json!({})).await;

    assert!(error_text(&bad_data).contains("listing Data must be an array"));
    assert!(error_text(&bad_next).contains("paging link must be a string"));
}
