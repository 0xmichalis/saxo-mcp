# saxo-mcp

Read-only MCP server for a [Saxo Bank](https://www.home.saxo) account through the
[Saxo OpenAPI](https://www.developer.saxo/openapi/learn): accounts, balances, positions,
orders, transaction history with costs, performance, instruments and prices. Written in
Rust, served over stdio.

It cannot trade. The gateway client sends only GET requests to fixed resource paths;
there is no generic request tool and no code path that sends anything else, so no prompt
can make it place, change or cancel an order.

## Tools

| Tool | Description |
|------|-------------|
| `saxo_session` | Environment (sim/live), session expiry, user and client records. Call first. |
| `saxo_accounts` | Accounts with their `AccountKey`, id, currency and type |
| `saxo_balances` | Cash, total value, open-position value, unrealized P&L, margin; whole client or one account |
| `saxo_positions` | `net` (default), `open` (with costs) or `closed` positions with prices, market value and P&L |
| `saxo_orders` | Working orders |
| `saxo_transactions` | Trades, fees, interest, dividends, transfers and corporate actions in a date range, with booked costs and FX conversion costs |
| `saxo_closed_positions` | Positions closed in a date range, with realized P&L and opening/closing costs |
| `saxo_performance` | Daily account value, cash transfers and time-weighted return, plus return, Sharpe, Sortino and drawdown |
| `saxo_performance_summary` | Allocation, trade activity and per-currency values for a period |
| `saxo_instrument_search` | Find instruments by keyword and asset type |
| `saxo_instrument_details` | Reference data for one instrument |
| `saxo_prices` | Snapshot quotes for up to 50 instruments of one asset type |

Results are Saxo's own JSON, with field names as in the
[OpenAPI reference](https://www.developer.saxo/openapi/referencedocs); paged listings are
gathered into one array with a `truncated` flag.

Things Saxo decides, not this server:

- **Prices** are delayed unless the account has real-time market data for the exchange
  and has accepted the OpenAPI market data terms (Saxo's platform settings). Without
  access, quotes come back with `PriceType` `NoAccess`. The server does not raise the
  session's trade level, so it stays read-only.
- **Closed positions** from `saxo_positions` stay empty for accounts on end-of-day
  netting; `saxo_closed_positions` reads them from Saxo's reports instead.
- **SIM** has no live market data and little history: performance tools ask for Saxo's
  mock data, and transactions may be empty.

## Security

- **What the server can do** is bounded by its code: GET requests only, to the gateway of
  the configured environment. HTTP redirects are not followed and Saxo's paging links are
  followed only while they point back into the gateway, so the bearer token is never sent
  anywhere else.
- **What the token can do** is set by Saxo, per application. Saxo assigns each app a set of
  claims; an app whose claims include Write access to personal resources yields tokens that
  could place orders if used by other software. The developer portal lists the claims it
  allocated to your app next to its AppKey. Treat the token file as a trading credential.
- The token file is created `0600` in a `0700` directory and replaced atomically. Errors and
  logs never include tokens, the AppSecret, authorization codes or token-endpoint bodies.

## Install

Prebuilt binaries are attached to each [GitHub Release](../../releases):

| Platform | Asset |
| --- | --- |
| Linux x86_64 | `saxo-mcp-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz` |
| macOS Apple Silicon | `saxo-mcp-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `saxo-mcp-vX.Y.Z-x86_64-apple-darwin.tar.gz` |

The Linux build is static (musl). Each asset ships with a `.sha256`.

```sh
target=x86_64-unknown-linux-musl   # or aarch64-apple-darwin, x86_64-apple-darwin
tar xzf "saxo-mcp-vX.Y.Z-${target}.tar.gz"
mkdir -p ~/.local/bin
install "saxo-mcp-vX.Y.Z-${target}/saxo-mcp" ~/.local/bin/
```

On macOS the binary is unsigned; clear Gatekeeper's quarantine with
`xattr -d com.apple.quarantine ~/.local/bin/saxo-mcp`.

Or build from source: `cargo build --release`.

## Setup

### 1. Create a Saxo OpenAPI application

1. Sign up for a free [developer account](https://www.developer.saxo/accounts/sim/signup);
   it comes with a simulation (SIM) account.
2. In [My Apps](https://www.developer.saxo/openapi/appmanagement), create an application
   with the **PKCE** grant type (no secret to store) or **Code** (Authorization Code with
   an AppSecret), and the redirect URL `http://localhost:8765/callback`.
3. Note the AppKey (and AppSecret for Code apps) and review the claims Saxo allocated.
   Personal data needs read access to personal resources; nothing here needs write
   access.

For your real account, link a funded Saxo account to the developer portal and
[request a LIVE application](https://www.developer.saxo/openapi/learn/direct-clients-request-for-openapi-application-credentials-for-the-live-environ).
SIM and LIVE apps have separate AppKeys.

### 2. Configure

Environment variables, or a `.env` file in the working directory (real environment
variables take precedence):

| Variable | Meaning |
| --- | --- |
| `SAXO_ENV` | `sim` (default) or `live` |
| `SAXO_APP_KEY` | The app's AppKey. Required. |
| `SAXO_APP_SECRET` | The AppSecret of a Code app. Leave unset for PKCE apps. |
| `SAXO_REDIRECT_URI` | The app's redirect URL, on `localhost` or `127.0.0.1`. Default `http://localhost:8765/callback`. |
| `SAXO_TOKEN_FILE` | Session file. Default `$XDG_STATE_HOME/saxo-mcp/<env>-tokens.json` (`~/.local/state/...`). |

### 3. Sign in

```sh
saxo-mcp auth
```

It prints a Saxo login URL and waits on the redirect address for Saxo to send the browser
back. On a headless host, forward the redirect port from the machine with the browser
first, then run `saxo-mcp auth` in that SSH session:

```sh
ssh -L 8765:localhost:8765 your-host
```

### Session lifetime

Saxo access tokens last minutes, and each refresh replaces the refresh token, whose own
lifetime is short as well. While the server runs, it refreshes ahead of expiry, so a
long-running MCP host keeps the session alive. If no server runs for longer than the
refresh token lives, run `saxo-mcp auth` again; tools say so when it is needed, and
running servers pick up the new session without a restart.

Several servers can share one token file (each refresh happens under a file lock), but do
not copy a token file to another machine and use both: the first refresh on either side
invalidates the other's refresh token. Sign in on each machine instead.

## Use with Claude Code

```sh
claude mcp add saxo -e SAXO_ENV=live -e SAXO_APP_KEY=your-app-key -- ~/.local/bin/saxo-mcp
```

Put `SAXO_APP_SECRET` in the environment or a `.env` file rather than on the command line.

## Use with a Hermes agent

```yaml
mcp_servers:
  saxo:
    command: /home/you/.local/bin/saxo-mcp
    args: []
    env:
      SAXO_ENV: live
      SAXO_APP_KEY: your-app-key
      SAXO_TOKEN_FILE: /home/you/.hermes/saxo-mcp/live-tokens.json
    timeout: 120
    connect_timeout: 60
```

Verify: `hermes mcp test saxo` should connect and list the tools; `saxo_session` confirms
the session.

## Development

```sh
cargo test        # unit + integration tests against local stand-ins (no network)
```

Pre-commit hooks (fmt, clippy, check, test) are installed by `cargo-husky` on the first
`cargo test`.

## License

MIT
