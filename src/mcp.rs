//! MCP server exposing read-only Saxo tools over stdio (via `rmcp`).
//!
//! Every tool reads; none can place, change or cancel an order or move money.
//! Results are Saxo's own JSON (field names as in the OpenAPI reference), with
//! paged listings gathered into one array.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData, ServerHandler, tool, tool_handler, tool_router};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::auth::unix_now;
use crate::config::Environment;
use crate::saxo::{Rows, SaxoClient, SaxoError, path_segment};

/// Rows a listing returns unless the caller asks for fewer or more.
const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 1000;
/// The simulation environment has no back office; its history endpoints serve
/// Saxo's mock data set when asked for it.
const SIM_MOCK_DATA_ID: &str = "001";

/// The MCP server: a gateway client, its environment, and the signed-in
/// client's ClientKey, which most non-`/me` resources need.
pub struct SaxoServer {
    client: SaxoClient,
    env: Environment,
    /// The ClientKey and the access token it was fetched with. A new login,
    /// picked up from the token file, may be another client's.
    client_key: Mutex<Option<(String, String)>>,
}

type Query = Vec<(&'static str, String)>;

impl SaxoServer {
    pub fn new(client: SaxoClient, env: Environment) -> Self {
        Self {
            client,
            env,
            client_key: Mutex::new(None),
        }
    }

    /// The signed-in client's ClientKey, fetched again whenever the access
    /// token changes.
    async fn client_key(&self) -> Result<String, SaxoError> {
        let token = self.client.tokens().access_token().await?;
        let mut cached = self.client_key.lock().await;
        if let Some((fetched_with, key)) = cached.as_ref()
            && *fetched_with == token
        {
            return Ok(key.clone());
        }
        let client = self.client.get("port/v1/clients/me", &[]).await?;
        let key = client
            .get("ClientKey")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| SaxoError::Parse("clients/me has no ClientKey".to_string()))?;
        *cached = Some((token, key.clone()));
        Ok(key)
    }

    /// Query parameters scoping a request to one account, or `None` for the
    /// whole client (the `/me` resources).
    async fn account_scope(&self, account_key: Option<&str>) -> Result<Option<Query>, SaxoError> {
        let Some(account_key) = non_blank(account_key) else {
            return Ok(None);
        };
        Ok(Some(vec![
            ("ClientKey", self.client_key().await?),
            ("AccountKey", account_key.to_string()),
        ]))
    }

    /// A `port/v1` listing for the whole client (`/me`) or one account.
    async fn portfolio_rows(
        &self,
        resource: &str,
        account_key: Option<&str>,
        mut query: Query,
        limit: Option<usize>,
    ) -> Result<Rows, SaxoError> {
        let path = match self.account_scope(account_key).await? {
            Some(scope) => {
                query.extend(scope);
                format!("port/v1/{resource}")
            }
            None => format!("port/v1/{resource}/me"),
        };
        self.rows(&path, query, limit.unwrap_or(DEFAULT_LIMIT))
            .await
    }

    async fn rows(&self, path: &str, mut query: Query, limit: usize) -> Result<Rows, SaxoError> {
        let limit = limit.clamp(1, MAX_LIMIT);
        query.push(("$top", limit.to_string()));
        self.client.get_rows(path, &query, limit).await
    }

    fn mock_data(&self, query: &mut Query) {
        if self.env == Environment::Sim {
            query.push(("MockDataId", SIM_MOCK_DATA_ID.to_string()));
        }
    }
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct NoArgs {}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AccountArgs {
    /// AccountKey from saxo_accounts. Omit for all accounts of the client.
    pub account_key: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PositionView {
    /// One row per instrument, netting all open positions in it.
    #[default]
    Net,
    /// Every open position separately, with its open price, time and costs.
    Open,
    /// Positions closed today; empty for clients on end-of-day netting.
    Closed,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PositionsArgs {
    /// "net" (default), "open" or "closed".
    #[serde(default)]
    pub view: PositionView,
    /// AccountKey from saxo_accounts. Omit for all accounts of the client.
    pub account_key: Option<String>,
    /// Most rows to return (default 200, at most 1000).
    pub limit: Option<usize>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct OrdersArgs {
    /// AccountKey from saxo_accounts. Omit for all accounts of the client.
    pub account_key: Option<String>,
    /// Most rows to return (default 200, at most 1000).
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
pub enum TransactionType {
    All,
    Trade,
    CashAmount,
    CashTransfer,
    CorporateAction,
}

impl TransactionType {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Trade => "Trade",
            Self::CashAmount => "CashAmount",
            Self::CashTransfer => "CashTransfer",
            Self::CorporateAction => "CorporateAction",
        }
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TransactionsArgs {
    /// First day, YYYY-MM-DD.
    pub from_date: String,
    /// Last day, YYYY-MM-DD. Defaults to today (UTC).
    pub to_date: Option<String>,
    /// Only these accounts (AccountKeys from saxo_accounts). Omit for all.
    pub account_keys: Option<Vec<String>>,
    /// "All" (default), "Trade", "CashAmount" (fees, interest, dividends…),
    /// "CashTransfer" (deposits and withdrawals) or "CorporateAction".
    pub transaction_type: Option<TransactionType>,
    /// Only these asset types, e.g. ["Stock", "Etf"].
    pub asset_types: Option<Vec<String>>,
    /// Only these instruments (Uics).
    pub uics: Option<Vec<u64>>,
    /// Most rows to return (default 200, at most 1000).
    pub limit: Option<usize>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DateRangeArgs {
    /// First day, YYYY-MM-DD.
    pub from_date: String,
    /// Last day, YYYY-MM-DD. Defaults to today (UTC).
    pub to_date: Option<String>,
    /// AccountKey from saxo_accounts. Omit for all accounts of the client.
    pub account_key: Option<String>,
    /// Most rows to return (default 200, at most 1000).
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
pub enum StandardPeriod {
    AllTime,
    Year,
    Quarter,
    Month,
}

impl StandardPeriod {
    fn as_str(self) -> &'static str {
        match self {
            Self::AllTime => "AllTime",
            Self::Year => "Year",
            Self::Quarter => "Quarter",
            Self::Month => "Month",
        }
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PerformanceArgs {
    /// Saxo's standard period: "AllTime", "Year", "Quarter" or "Month". Used when
    /// from_date is not given; defaults to "Year".
    pub period: Option<StandardPeriod>,
    /// First day, YYYY-MM-DD, instead of a standard period.
    pub from_date: Option<String>,
    /// Last day, YYYY-MM-DD, with from_date. Defaults to today (UTC).
    pub to_date: Option<String>,
    /// AccountKey from saxo_accounts. Omit for all accounts of the client.
    pub account_key: Option<String>,
    /// Saxo FieldGroups to return. Time series: Balance, Balance_AccountValue,
    /// Balance_AccountBalance, Balance_Accruals, Balance_Cash,
    /// Balance_CashTransfer, Balance_SecurityTransfer, Balance_MonthlyProfitLoss,
    /// Balance_YearlyProfitLoss, TimeWeighted,
    /// TimeWeighted_Accumulated, TimeWeighted_MonthlyReturn,
    /// TimeWeighted_YearlyReturn, KeyFigures, Benchmark, All. Summary:
    /// Allocation, TradeActivity, TradeSummary, TotalCashBalancePerCurrency,
    /// TotalPositionsValuePerCurrency, TotalPositionsValuePerProductPerSecurity,
    /// BenchMark, All.
    pub field_groups: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct InstrumentSearchArgs {
    /// Words to match in the symbol or description, e.g. "apple" or "AAPL".
    pub keywords: String,
    /// Only these asset types, e.g. ["Stock", "Etf", "FxSpot", "StockOption"].
    pub asset_types: Option<Vec<String>>,
    /// Most rows to return (default 25, at most 1000).
    pub limit: Option<usize>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct InstrumentArgs {
    /// The instrument's Uic, from saxo_instrument_search (Identifier) or a position.
    pub uic: u64,
    /// The instrument's asset type, e.g. "Stock".
    pub asset_type: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PricesArgs {
    /// Distinct Uics of instruments that share `asset_type`, at most 50.
    pub uics: Vec<u64>,
    /// The instruments' asset type, e.g. "Stock".
    pub asset_type: String,
}

#[tool_router]
impl SaxoServer {
    #[tool(
        name = "saxo_session",
        description = "Who and where this server is signed in as: the Saxo environment \
                       (sim or live), when the session's tokens expire (Unix seconds), and \
                       the user and client records (ClientKey, default account and \
                       currency, position netting mode). Call this first to check the \
                       session works.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn session(&self, _: Parameters<NoArgs>) -> Result<CallToolResult, ErrorData> {
        let result = async {
            let session = self.client.tokens().status().await?;
            let (user, client) = tokio::try_join!(
                self.client.get("port/v1/users/me", &[]),
                self.client.get("port/v1/clients/me", &[])
            )?;
            Ok(json!({ "session": session, "user": user, "client": client }))
        }
        .await;
        Ok(to_result(result))
    }

    #[tool(
        name = "saxo_accounts",
        description = "List the client's Saxo accounts: AccountKey (what other tools take), \
                       AccountId, currency, account type and whether it is active.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn accounts(&self, _: Parameters<NoArgs>) -> Result<CallToolResult, ErrorData> {
        let result = self
            .rows("port/v1/accounts/me", Vec::new(), MAX_LIMIT)
            .await
            .map(|rows| named("accounts", rows));
        Ok(to_result(result))
    }

    #[tool(
        name = "saxo_balances",
        description = "Balances in the account currency: cash, total account value, value \
                       of open positions, unrealized P&L, margin used and available, cost \
                       to close positions and unbooked transactions. Whole client by \
                       default, or one account.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn balances(
        &self,
        Parameters(args): Parameters<AccountArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = async {
            match self.account_scope(args.account_key.as_deref()).await? {
                Some(scope) => self.client.get("port/v1/balances", &scope).await,
                None => self.client.get("port/v1/balances/me", &[]).await,
            }
        }
        .await;
        Ok(to_result(result))
    }

    #[tool(
        name = "saxo_positions",
        description = "Current positions with instrument, amount, open price, current price \
                       (and how delayed it is), market value, P&L in instrument and account \
                       currency, FX conversion P&L and trade costs. view: \"net\" (default) \
                       nets per instrument; \"open\" lists each position with its open time \
                       and open/close costs; \"closed\" lists positions closed today, which \
                       is always empty for clients on end-of-day netting (use \
                       saxo_closed_positions for history). Without market data access the \
                       current price and P&L are missing.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn positions(
        &self,
        Parameters(args): Parameters<PositionsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let (resource, field_groups) = match args.view {
            PositionView::Net => (
                "netpositions",
                "NetPositionBase,NetPositionView,DisplayAndFormat,ExchangeInfo",
            ),
            PositionView::Open => (
                "positions",
                "PositionBase,PositionView,Costs,DisplayAndFormat,ExchangeInfo",
            ),
            PositionView::Closed => (
                "closedpositions",
                "ClosedPosition,DisplayAndFormat,ExchangeInfo",
            ),
        };
        let result = self
            .portfolio_rows(
                resource,
                args.account_key.as_deref(),
                vec![("FieldGroups", field_groups.to_string())],
                args.limit,
            )
            .await
            .map(|rows| named("positions", rows));
        Ok(to_result(result))
    }

    #[tool(
        name = "saxo_orders",
        description = "Working (open) orders: instrument, side, amount and filled amount, \
                       order type and price, duration, status, distance to market and \
                       related orders.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn orders(
        &self,
        Parameters(args): Parameters<OrdersArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = self
            .portfolio_rows(
                "orders",
                args.account_key.as_deref(),
                vec![("FieldGroups", "DisplayAndFormat,ExchangeInfo".to_string())],
                args.limit,
            )
            .await
            .map(|rows| named("orders", rows));
        Ok(to_result(result))
    }

    #[tool(
        name = "saxo_transactions",
        description = "Transaction history for a date range: trades, cash amounts (fees, \
                       interest, dividends, custody), cash transfers and corporate actions. \
                       Each has the booked amount, TotalCost, ConversionCost and \
                       ConversionRate, realized P&L, and Bookings with Saxo's cost classes \
                       (TransactionCosts, OngoingCosts, AncillaryCosts…) and Trades with \
                       price, quantity and SpreadCost. Amounts are in the client's \
                       currency. Recent rows may be intraday and incomplete \
                       (IsIntradayData).",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn transactions(
        &self,
        Parameters(args): Parameters<TransactionsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = async {
            let (from, to) = date_range(&args.from_date, args.to_date.as_deref())?;
            let mut query = vec![
                ("ClientKey", self.client_key().await?),
                ("FromDate", from),
                ("ToDate", to),
            ];
            if let Some(keys) = args.account_keys.filter(|k| !k.is_empty()) {
                query.push(("AccountKeys", keys.join(",")));
            }
            if let Some(kind) = args.transaction_type {
                query.push(("TransactionType", kind.as_str().to_string()));
            }
            if let Some(types) = args.asset_types.filter(|t| !t.is_empty()) {
                query.push(("AssetTypes", asset_types(&types)?));
            }
            if let Some(uics) = args.uics.filter(|u| !u.is_empty()) {
                let uics: Vec<String> = uics.iter().map(u64::to_string).collect();
                query.push(("Uics", uics.join(",")));
            }
            self.rows(
                "hist/v1/transactions",
                query,
                args.limit.unwrap_or(DEFAULT_LIMIT),
            )
            .await
        }
        .await
        .map(|rows| named("transactions", rows));
        Ok(to_result(result))
    }

    #[tool(
        name = "saxo_closed_positions",
        description = "Positions closed in a date range, from Saxo's reports: open and close \
                       price and time, amount, realized P&L and its FX component, and \
                       opening and closing costs, in instrument and account currency. \
                       The simulation environment returns Saxo's demo data.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn closed_positions(
        &self,
        Parameters(args): Parameters<DateRangeArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = async {
            let (from, to) = date_range(&args.from_date, args.to_date.as_deref())?;
            let path = format!(
                "cs/v1/reports/closedPositions/{}/{from}/{to}",
                path_segment(&self.client_key().await?)
            );
            let mut query = Vec::new();
            if let Some(account_key) = non_blank(args.account_key.as_deref()) {
                query.push(("AccountKey", account_key.to_string()));
            }
            self.rows(&path, query, args.limit.unwrap_or(DEFAULT_LIMIT))
                .await
        }
        .await
        .map(|rows| named("closed_positions", rows));
        Ok(to_result(result))
    }

    #[tool(
        name = "saxo_performance",
        description = "Account performance over time as daily {Date, Value} series: \
                       account value, cash transfers, time-weighted return, plus key \
                       figures (return, Sharpe and Sortino ratios, max drawdown). Values \
                       come from Saxo's end-of-day processing, include costs and FX P&L, \
                       and exist only for market days. Defaults: period \"Year\", field \
                       groups Balance_AccountValue, Balance_CashTransfer, \
                       TimeWeighted_Accumulated and KeyFigures. The simulation \
                       environment returns Saxo's mock data.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn performance(
        &self,
        Parameters(args): Parameters<PerformanceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = self
            .performance_report(
                "hist/v4/performance/timeseries",
                "Balance_AccountValue,Balance_CashTransfer,TimeWeighted_Accumulated,KeyFigures",
                args,
            )
            .await;
        Ok(to_result(result))
    }

    #[tool(
        name = "saxo_performance_summary",
        description = "Performance summary for a period: allocation by asset type and \
                       currency, trade activity and trade summary, cash and position values \
                       per currency, and positions per product. Same period arguments as \
                       saxo_performance; field groups default to All. The simulation \
                       environment returns Saxo's mock data.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn performance_summary(
        &self,
        Parameters(args): Parameters<PerformanceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = self
            .performance_report("hist/v4/performance/summary", "All", args)
            .await;
        Ok(to_result(result))
    }

    #[tool(
        name = "saxo_instrument_search",
        description = "Find instruments by keyword: Identifier, SummaryType, asset type, \
                       symbol, description, exchange and currency. When SummaryType is \
                       \"Instrument\", Identifier is the Uic to use with its asset type in \
                       saxo_instrument_details and saxo_prices. A \"ContractOptionRoot\" \
                       row is an option root, not a contract: its Identifier is not a Uic.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn instrument_search(
        &self,
        Parameters(args): Parameters<InstrumentSearchArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = async {
            let keywords = args.keywords.trim();
            if keywords.is_empty() {
                return Err(SaxoError::Invalid("keywords must not be empty".to_string()));
            }
            let mut query = vec![("Keywords", keywords.to_string())];
            if let Some(types) = args.asset_types.filter(|t| !t.is_empty()) {
                query.push(("AssetTypes", asset_types(&types)?));
            }
            self.rows("ref/v1/instruments", query, args.limit.unwrap_or(25))
                .await
        }
        .await
        .map(|rows| named("instruments", rows));
        Ok(to_result(result))
    }

    #[tool(
        name = "saxo_instrument_details",
        description = "Reference data for one instrument: description, exchange, currency, \
                       tradability, lot and tick sizes, minimum trade size, and for \
                       derivatives the underlying, expiry and contract size.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn instrument_details(
        &self,
        Parameters(args): Parameters<InstrumentArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = async {
            let path = format!(
                "ref/v1/instruments/details/{}/{}",
                args.uic,
                asset_type(&args.asset_type)?
            );
            self.client.get(&path, &[]).await
        }
        .await;
        Ok(to_result(result))
    }

    #[tool(
        name = "saxo_prices",
        description = "Snapshot quotes (bid, ask, mid, last traded, open, last close, \
                       volume) for up to 50 instruments of one asset type. \
                       Quote.DelayedByMinutes says how old a price is (0 = real time); \
                       PriceTypeBid/PriceTypeAsk \"NoAccess\" means the account lacks market \
                       data for that exchange or has not accepted Saxo's OpenAPI market \
                       data terms. The simulation environment quotes FX but returns NoAccess \
                       for stocks.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn prices(
        &self,
        Parameters(args): Parameters<PricesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = async {
            let mut uics = args.uics;
            uics.sort_unstable();
            uics.dedup();
            if uics.is_empty() || uics.len() > 50 {
                return Err(SaxoError::Invalid("pass between 1 and 50 uics".to_string()));
            }
            let list: Vec<String> = uics.iter().map(u64::to_string).collect();
            let query = [
                ("Uics", list.join(",")),
                ("AssetType", asset_type(&args.asset_type)?.to_string()),
                (
                    "FieldGroups",
                    "Quote,PriceInfo,PriceInfoDetails,DisplayAndFormat".to_string(),
                ),
            ];
            self.client
                .get_rows("trade/v1/infoprices/list", &query, uics.len())
                .await
        }
        .await
        .map(|rows| named("prices", rows));
        Ok(to_result(result))
    }
}

impl SaxoServer {
    async fn performance_report(
        &self,
        path: &str,
        default_field_groups: &str,
        args: PerformanceArgs,
    ) -> Result<Value, SaxoError> {
        let mut query = vec![("ClientKey", self.client_key().await?)];
        match args.from_date.as_deref() {
            Some(from) => {
                let (from, to) = date_range(from, args.to_date.as_deref())?;
                query.push(("FromDate", from));
                query.push(("ToDate", to));
            }
            None => query.push((
                "StandardPeriod",
                args.period
                    .unwrap_or(StandardPeriod::Year)
                    .as_str()
                    .to_string(),
            )),
        }
        if let Some(account_key) = non_blank(args.account_key.as_deref()) {
            query.push(("AccountKey", account_key.to_string()));
        }
        let field_groups = match args.field_groups.filter(|g| !g.is_empty()) {
            Some(groups) => names(&groups, "field group")?,
            None => default_field_groups.to_string(),
        };
        query.push(("FieldGroups", field_groups));
        self.mock_data(&mut query);
        self.client.get(path, &query).await
    }
}

#[tool_handler]
impl ServerHandler for SaxoServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Read-only access to the user's Saxo Bank account through the Saxo OpenAPI. \
                 Start with `saxo_session` to confirm the session and environment, then \
                 `saxo_accounts` for AccountKeys. Holdings: `saxo_balances`, \
                 `saxo_positions`, `saxo_orders`. History and costs: \
                 `saxo_transactions`, `saxo_closed_positions`. Performance: \
                 `saxo_performance`, `saxo_performance_summary`. Instruments: \
                 `saxo_instrument_search`, `saxo_instrument_details`, `saxo_prices`. \
                 Amounts are in the currency the field or record names. Dates are \
                 YYYY-MM-DD. Nothing here can trade. If a tool says the session ended, \
                 the user must run `saxo-mcp auth`.",
            )
    }
}

fn non_blank(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

/// Asset types are Saxo enum names; refuse anything else before it reaches a
/// URL.
fn asset_type(value: &str) -> Result<&str, SaxoError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 40 || !value.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(SaxoError::Invalid(format!(
            "asset type must be a Saxo AssetType name such as \"Stock\", got {value:?}"
        )));
    }
    Ok(value)
}

fn asset_types(values: &[String]) -> Result<String, SaxoError> {
    let types = values
        .iter()
        .map(|t| asset_type(t))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(types.join(","))
}

/// Saxo enum names (field groups and the like): letters, digits and `_`.
fn names(values: &[String], what: &str) -> Result<String, SaxoError> {
    let names = values
        .iter()
        .map(|value| {
            let value = value.trim();
            let valid = !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_');
            valid
                .then_some(value)
                .ok_or_else(|| SaxoError::Invalid(format!("unknown {what} {value:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names.join(","))
}

/// Validate a `from`..`to` range of YYYY-MM-DD dates, `to` defaulting to today.
fn date_range(from: &str, to: Option<&str>) -> Result<(String, String), SaxoError> {
    let from = parse_date(from)?;
    let to = match to {
        Some(to) => parse_date(to)?,
        None => today(),
    };
    if from > to {
        return Err(SaxoError::Invalid(format!(
            "from_date {from} is after to_date {to}"
        )));
    }
    Ok((from, to))
}

fn parse_date(value: &str) -> Result<String, SaxoError> {
    let value = value.trim();
    let invalid = || SaxoError::Invalid(format!("dates must be YYYY-MM-DD, got {value:?}"));
    let bytes = value.as_bytes();
    let shape_ok = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
    if !shape_ok {
        return Err(invalid());
    }
    let month: u32 = value[5..7].parse().map_err(|_| invalid())?;
    let day: u32 = value[8..10].parse().map_err(|_| invalid())?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(invalid());
    }
    Ok(value.to_string())
}

/// Today's date in UTC, YYYY-MM-DD.
fn today() -> String {
    let (year, month, day) = civil_from_days((unix_now() / 86_400) as i64);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The proleptic Gregorian date `days` days after 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn named(name: &str, rows: Rows) -> Value {
    let mut value = json!({ name: rows.rows, "truncated": rows.truncated });
    if let Some(total) = rows.total {
        value["total"] = json!(total);
    }
    value
}

/// Map a client outcome to an MCP tool result. A failure is a tool-level error
/// (`is_error = true`) so the model sees the message, rather than a protocol error.
fn to_result(result: Result<Value, SaxoError>) -> CallToolResult {
    match result {
        Ok(value) => CallToolResult::structured(value),
        Err(err) => CallToolResult::error(vec![ContentBlock::text(err.to_string())]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_map_to_structured_json_and_errors_to_tool_errors() {
        let ok = to_result(Ok(json!({ "accounts": [{ "AccountId": "1" }] })));
        assert_ne!(ok.is_error, Some(true));
        let json = serde_json::to_string(&ok).unwrap();
        assert!(json.contains("structuredContent"), "{json}");

        let err = to_result(Err(SaxoError::Invalid("bad input".to_string())));
        assert_eq!(err.is_error, Some(true));
        assert!(serde_json::to_string(&err).unwrap().contains("bad input"));
    }

    #[test]
    fn asset_types_and_names_must_be_plain_identifiers() {
        assert_eq!(asset_type(" Stock ").unwrap(), "Stock");
        for bad in ["", "Stock/../x", "Fx Spot", "a?b", "Stock,Etf"] {
            assert!(asset_type(bad).is_err(), "{bad:?}");
        }
        let groups = [
            "KeyFigures".to_string(),
            " Balance_AccountValue".to_string(),
        ];
        assert_eq!(
            names(&groups, "field group").unwrap(),
            "KeyFigures,Balance_AccountValue"
        );
        assert!(names(&["All&x=1".to_string()], "field group").is_err());
    }

    #[test]
    fn dates_are_validated_and_ordered() {
        assert_eq!(
            date_range("2026-01-01", Some(" 2026-03-31 ")).unwrap(),
            ("2026-01-01".to_string(), "2026-03-31".to_string())
        );
        for bad in [
            "2026-1-01",
            "2026/01/01",
            "2026-13-01",
            "2026-01-32",
            "20260101",
            "x",
        ] {
            assert!(parse_date(bad).is_err(), "{bad:?}");
        }
        let err = date_range("2026-02-01", Some("2026-01-31")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "from_date 2026-02-01 is after to_date 2026-01-31"
        );
        let (_, to) = date_range("2000-01-01", None).unwrap();
        assert_eq!(to, today());
    }

    #[test]
    fn civil_dates_match_known_days() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_773), (2026, 11, 16));
        assert_eq!(civil_from_days(20_819), (2027, 1, 1));
    }

    #[test]
    fn listings_report_truncation_and_total() {
        let rows = Rows {
            rows: vec![json!(1)],
            total: Some(3),
            truncated: true,
        };
        assert_eq!(
            named("orders", rows),
            json!({ "orders": [1], "truncated": true, "total": 3 })
        );
    }
}
