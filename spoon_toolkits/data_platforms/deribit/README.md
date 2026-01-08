
## SpoonOS quick start (for Spoon developers)

This section is for SpoonOS developers who want to call Deribit via the
`spoon-toolkit` integration and MCP tools, instead of using the Python APIs
directly.

### Environment configuration

Deribit credentials and network selection are provided via environment
variables (or a `.env` file):

```bash
# Required
DERIBIT_CLIENT_ID=your_client_id
DERIBIT_CLIENT_SECRET=your_client_secret

# Network selection
DERIBIT_USE_TESTNET=true   # "true" for testnet, "false" for mainnet
```

Recommended workflow:

- Start with **testnet** (`DERIBIT_USE_TESTNET=true`) for development and
  dry‑runs.
- Only switch to **mainnet** when you have:
  - Verified market data, account, and trading tools on testnet.
  - Implemented your own risk controls at the application / agent layer.

All tools read configuration via `DeribitConfig` in `env.py`.

---

## Integration with Spoon framework / MCP

Deribit tools are designed to be exposed to Spoon agents through MCP servers
and through the `spoon_toolkits` package.

At a high level:

- The **Python tool classes** (for example `GetInstrumentsTool`,
  `PlaceBuyOrderTool`) are the building blocks.
- In Spoon, these tools are typically:
  - Registered via an MCP server module that imports and exposes all tools,
    or
  - Imported directly from `spoon_toolkits.data_platforms.deribit` in your
    own custom MCP server.

When integrating with Spoon:

- Treat each Deribit tool as a **single RPC‑like operation**.
- Use Spoon’s tool configuration (YAML or Python) to:
  - Wire in the Deribit MCP server.
  - Ensure the necessary environment variables are present in the SpoonOS
    runtime.

> The integration pattern is intentionally similar to the existing
> `desearch` and `chainbase` toolkits: you configure environment variables,
> register the MCP server, and then call tools by name from Spoon agents.

---

## Mapping: Deribit JSON‑RPC → Deribit tools

The table below maps Deribit’s official JSON‑RPC endpoints (as documented on
`https://docs.deribit.com/`) to the corresponding tools in this toolkit.
This is useful when you read Deribit’s docs and want to know “which tool
should I call from Spoon”.

| Deribit JSON‑RPC method                    | Toolkit tool             | Notes                                              |
|--------------------------------------------|--------------------------|----------------------------------------------------|
| `public/get_instruments`                   | `GetInstrumentsTool`     | List instruments by `currency`, `kind`, etc.       |
| `public/get_ticker`                        | `GetTickerTool`          | Ticker, mark price, last price, best bid/ask.      |
| `public/get_order_book`                    | `GetOrderBookTool`       | Level‑2 order book for an instrument.              |
| `public/get_last_trades_by_instrument`     | `GetLastTradesTool`      | Recent trades for an instrument.                   |
| `public/get_index_price`                   | `GetIndexPriceTool`      | Index price for an index.                          |
| `private/get_account_summary`              | `GetAccountSummaryTool`  | Account balances, equity, margin, etc.             |
| `private/get_positions`                    | `GetPositionsTool`       | Open positions by `currency` / `kind`.             |
| `private/get_open_orders_by_instrument`    | `GetOpenOrdersTool`      | Open orders for a specific instrument.             |
| `private/get_order_history_by_instrument`  | `GetOrderHistoryTool`    | Order history for an instrument.                   |
| `private/get_trades_by_instrument`         | `GetTradeHistoryTool`    | Trade history for an instrument.                   |
| `private/buy`                              | `PlaceBuyOrderTool`      | Place buy orders (spot / futures / options).       |
| `private/sell`                             | `PlaceSellOrderTool`     | Place sell orders (spot / futures / options).      |
| `private/cancel`                           | `CancelOrderTool`        | Cancel a single order by ID.                       |
| `private/cancel_all_by_currency` / `kind`  | `CancelAllOrdersTool`    | Cancel all open orders by `currency` / `kind`.     |

The tools may perform additional **spec‑based validation** (contract size,
tick size, etc.) before calling Deribit; see the error handling section
below for details.

---

## Typical workflows for SpoonOS

This section describes high‑level workflows that you can implement in Spoon
agents by calling the tools in sequence. It is intentionally
language‑agnostic (no Python code).

### 1. Spot round‑trip (safe functional test)

Goal: verify spot trading tools and contract‑size validation with minimal
risk.

1. **Discover instruments**
   - Call `GetInstrumentsTool(currency="ETH", kind="spot", expired=False)`.
   - Prefer instruments containing `USDC` or `USDT` in `instrument_name`.
2. **Fetch current price**
   - Call `GetTickerTool(instrument_name=...)`.
   - Use `last_price` or `mark_price` as the reference.
3. **Place a deep, non‑filling limit order**
   - Call `PlaceBuyOrderTool` or `PlaceSellOrderTool` with:
     - `order_type="limit"`
     - `post_only=True`
     - `price` set far away from the current price (for example
       30–40% away).
   - The toolkit will:
     - Validate `amount` against `contract_size`.
     - Validate `price` against `tick_size`.
4. **Verify and cancel**
   - Call `GetOpenOrdersTool(instrument_name=...)` to confirm the order
     appears.
   - Cancel it using `CancelOrderTool(order_id=...)` or
     `CancelAllOrdersTool(currency="ETH", kind="spot")`.

This pattern is used by `test_spot_trading.py` and
`test_0.02eth_safe_trading.py`.

### 2. Futures open + close (low‑risk directional test)

Goal: ensure futures buy/sell tools and position reporting work correctly.

1. **Check current positions**
   - Call `GetPositionsTool(currency="ETH", kind="future")`.
   - Decide whether it is safe to open a small test position
     (for example, no large existing exposure).
2. **Fetch futures price**
   - Call `GetTickerTool(instrument_name="ETH-PERPETUAL")`.
3. **Open a small position**
   - Call `PlaceBuyOrderTool` with:
     - `instrument_name="ETH-PERPETUAL"`
     - `order_type="market"` (for functional test), or a deep `limit` for
       non‑filling tests.
     - `amount=1.0` (or a very small size, depending on your risk policy).
4. **Verify position**
   - Call `GetPositionsTool` again to confirm a non‑zero size.
5. **Close the position**
   - Call `PlaceSellOrderTool` with:
     - `instrument_name="ETH-PERPETUAL"`
     - `order_type="market"`
     - `amount` equal to the current long size (do not oversell).
6. **Final checks**
   - Ensure `GetPositionsTool` reports zero size.
   - Optionally call `GetOpenOrdersTool` to confirm no open futures orders
     remain.

This pattern is implemented (with extra logging and funding tracking) in
`test_complete_trading_workflow.py` and `test_all_trading_types.py`.

### 3. Options safe round‑trip (recommended pattern)

Goal: test options functionality with a very small balance, minimizing risk
and avoiding tick‑size issues.

This pattern is also described in `TRADING_EXPERIENCE.md` and implemented in
`test_options_safe_roundtrip.py`:

1. **Select a cheap ETH option**
   - Use `GetInstrumentsTool(currency="ETH", kind="option", expired=False)`
     to list options.
   - For each candidate instrument:
     - Call `GetTickerTool(instrument_name=...)` to read `mark_price`.
     - Compute `estimated_cost = mark_price × contract_size`.
   - Filter to options where `estimated_cost` is:
     - Far below the current account balance.
     - Below a hard cap (for example `0.005 ETH`).
   - Pick the **cheapest** option that passes those filters.
2. **Buy 1 contract using a market order**
   - Call `PlaceBuyOrderTool` with:
     - `order_type="market"`
     - `amount=1.0` (1 contract, or 1×`contract_size`).
   - Let the matching engine decide the actual fill price and handle
     tick‑size / price‑band rules.
3. **Verify position**
   - Call `GetPositionsTool(currency="ETH", kind="option")`.
   - Find the instrument with `size > 0` (the option you just bought).
4. **Sell using reduce‑only market order**
   - Call `PlaceSellOrderTool` with:
     - `order_type="market"`
     - `amount` equal to the current long size.
     - `reduce_only=True` (ensure this only closes the position, never
       opens a short).
5. **Final checks**
   - Verify balances and positions using `GetAccountSummaryTool` and
     `GetPositionsTool`.
   - Check recent trades using `GetTradeHistoryTool`.

This pattern is the safest way to validate options trading end‑to‑end on a
small account.

---

## Error handling and validation

Deribit tools perform two layers of validation:

1. **Toolkit‑level validation (pre‑flight)**
   - Required parameters: `instrument_name`, `amount`, and `price`
     (for limit orders).
   - Basic checks: values must be positive and non‑null.
   - Spec‑based checks using `GetInstrumentsTool`:
     - `amount` must be a multiple of `contract_size`.
     - `price` must conform to `tick_size` for the instrument.
   - If these checks fail, the tool:
     - **Does not call the Deribit API**.
     - Returns a structured error (typically a dict with an `"error"` field
       and, where possible, suggested adjusted values).

2. **Deribit API errors**
   - Even after local validation, Deribit may return errors due to:
     - Insufficient funds.
     - Internal price bands / additional tick rules (especially for
       options).
     - Network or internal server issues.

Spoon developers should treat these as **normal, expected conditions** and
handle them in their own logic. Some common cases:

- **`must be a multiple of contract size`**
  - Origin: Deribit or toolkit.
  - Action:
    - Read `contract_size` from the error (or from `GetInstrumentsTool`).
    - Adjust `amount` to the suggested multiple.
    - At the agent layer, you can either reduce trade size or explain the
      required contract size to the end user.

- **`must conform to tick size`**
  - Origin: Deribit or toolkit.
  - Cause:
    - Price not aligned with `tick_size`, or not within internal price
      bands.
  - Action:
    - Use the `tick_size` returned by the toolkit.
    - Adjust prices by rounding to multiples of `tick_size`.
    - For options, consider using market orders as described in the safe
      options pattern instead of complex limit‑order logic inside the core
      tool layer.

- **`not_enough_funds`**
  - Origin: Deribit API.
  - Action:
    - Re‑check account balance via `GetAccountSummaryTool`.
    - Decide at the strategy / application layer whether to:
      - Reduce position size.
      - Skip the trade.
      - Ask the user to deposit more funds.

In general:

- **Toolkit errors** (validation failures) are your signal that the request
  is malformed at the spec level.
- **Deribit errors** are your signal that the trade is valid in shape, but
  not executable under current account or market conditions.

---

## Recommended examples and docs for Spoon developers

When integrating into SpoonOS, you rarely want to run all examples;
instead, use a small curated subset:

- **Core documentation**
  - This file: high‑level overview, tools list, and Spoon integration
    hints.
  - `TRADING_EXPERIENCE.md`: detailed trading notes (contract sizes,
    tick sizes, options quirks, safe patterns).

- **Read‑only / smoke tests**
  - `examples/test_public_api.py`
  - `examples/test_authentication.py`
  - `examples/test_market_data_tools.py`
  - `examples/test_account_tools.py`
  - `examples/test_mainnet_readonly.py` (mainnet read‑only, safe to run
    with real funds).

- **Spot / futures functional tests**
  - `examples/test_spot_trading.py` – safe spot limit‑order test
    (deep limit + cancel).
  - `examples/test_0.02eth_safe_trading.py` – safe futures test for very
    small balances.
  - `examples/test_complete_trading_workflow.py` – end‑to‑end
    spot + futures workflow.
  - `examples/test_all_trading_types.py` – combined spot + futures +
    options test, with full cleanup.

- **Options functional tests**
  - `examples/test_options_safe_roundtrip.py` – **recommended default** for
    options; small‑risk buy+sell pattern.
  - `examples/test_options_complete.py` – more detailed options workflow,
    including logs and funding tracking.
  - `examples/test_options_auto_trade.py`,
    `examples/test_options_close_position.py`,
    `examples/test_options_trading.py` – additional options examples and
    diagnostics.

These `examples/` are meant as reference workflows and regression tests,
not as a public API. In SpoonOS agents, you should always call the tool
classes (`GetInstrumentsTool`, `PlaceBuyOrderTool`, etc.) directly and
apply your own business logic, risk management, and UX layer on top.
# Deribit API Integration Toolkit

Deribit integration for the `spoon_toolkits` project.  
This module provides typed tools for the Deribit JSON‑RPC API
(market data, account, and trading), suitable for use both directly
and via MCP.

> **Note:** This README is written for the upstream `spoon-toolkit`
> repository. Paths below assume the package layout\n> `spoon_toolkits/data_platforms/deribit/`.

---

## Quick start

### Install (editable)

From the `spoon-toolkit` project root:

```bash
pip install -e .
```

### Configuration

Create a `.env` file that provides Deribit credentials and network:

```bash
DERIBIT_CLIENT_ID=your_client_id
DERIBIT_CLIENT_SECRET=your_client_secret
DERIBIT_USE_TESTNET=true  # \"true\" for testnet, \"false\" for mainnet
```

The module reads configuration via `DeribitConfig` in `env.py`.

---

## Usage

You can use the tools either through the top‑level `spoon_toolkits`
package or via the `deribit` submodule.

### Option 1: Import from the main package (recommended)

```python
from spoon_toolkits import (
    GetInstrumentsTool,
    GetTickerTool,
    PlaceBuyOrderTool,
)

async def main():
    tool = GetInstrumentsTool()
    result = await tool.execute(currency=\"BTC\", kind=\"future\")
    print(result)
```

### Option 2: Import from the `deribit` submodule

```python
from spoon_toolkits.data_platforms.deribit import (
    GetInstrumentsTool,
    GetTickerTool,
    PlaceBuyOrderTool,
)
```

### Option 3: Use via MCP

```python
from spoon_toolkits.data_platforms.deribit import deribit_mcp

# deribit_mcp is a FastMCP instance that exposes all Deribit tools
# over the MCP protocol.
```

---

## Tools overview

### Market data tools (public API)

- `GetInstrumentsTool` – list instruments
- `GetOrderBookTool` – order book
- `GetTickerTool` – ticker / mark price
- `GetLastTradesTool` – recent trades
- `GetIndexPriceTool` – index price
- `GetBookSummaryTool` – book summary

### Account tools (private API)

- `GetAccountSummaryTool` – account summary
- `GetPositionsTool` – open positions
- `GetOrderHistoryTool` – order history
- `GetTradeHistoryTool` – trade history

### Trading tools (private API)

- `PlaceBuyOrderTool` – place buy orders
- `PlaceSellOrderTool` – place sell orders
- `CancelOrderTool` – cancel a single order
- `CancelAllOrdersTool` – cancel all open orders for a currency/kind
- `GetOpenOrdersTool` – list open orders by instrument
- `EditOrderTool` – edit an existing order

---

## Examples and testing

The `examples/` directory contains end‑to‑end scripts demonstrating
how to use the tools safely with small balances:

- Spot and futures:
  - `test_spot_trading.py`
  - `test_0.02eth_safe_trading.py`
  - `test_complete_trading_workflow.py`
  - `test_all_trading_types.py`
- Options:
  - `test_options_safe_roundtrip.py` – picks a cheap ETH option and\n    performs a buy + sell round trip (with detailed logging).
  - `test_options_complete.py` – more detailed options workflow tests.

For a higher‑level summary of lessons learned (contract sizes, tick sizes,
options quirks, and safe patterns), see:

- `TRADING_EXPERIENCE.md`

For API‑level smoke tests (market data, account, auth) see:

- `examples/test_public_api.py`
- `examples/test_authentication.py`
- `examples/test_market_data_tools.py`
- `examples/test_account_tools.py`

---

## Development notes

- Core implementation lives under:

  ```text
  spoon_toolkits/data_platforms/deribit/
  ```

- The Deribit JSON‑RPC client is in `jsonrpc_client.py` and is reused by
  all tools.
- Tools are implemented in `market_data.py`, `account.py`, and `trading.py`.
- Higher‑level test workflows and debug scripts reside in `examples/` and
  are **not** part of the public API surface.

