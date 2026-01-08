# Deribit Trading Experience Summary (Spot / Futures / Options)

This document summarizes the main pitfalls and best practices we discovered while integrating
Deribit into `spoon_toolkits` and running small real-money tests. It is written for developers
who want to use the `deribit` tools safely and predictably.

## 1. Spot (Spot) Trading

### 1.1 Typical error: `must be a multiple of contract size`

**Symptom** (HTTP 400):
- `reason: "must be a multiple of contract size"`
- `param: "amount"`

**Cause:**
- Some spot instruments (e.g. `ETH_USDC`) are exposed as contracts.
- The `amount` must be an integer multiple of the instrument `contract_size`
  (for example `0.0001`).

**Best practices:**
- Always call `GetInstrumentsTool` first and read `contract_size`.
- Use `Decimal` to check `amount % contract_size == 0` before sending the order.
- In the toolkit we validate this at the tool level and, on failure, return
  a clear error with a suggested `amount` that conforms to `contract_size`.

### 1.2 Safe testing strategy

When testing with small balances:
- Use very small `amount` values (e.g. a few thousandths of an ETH) for spot buy/sell.
- For “logic only” tests, use **limit orders far away from the market price**, so that
  the order does not actually fill.
- Only switch to market orders or near-touch limit orders when you genuinely want real fills.

## 2. Futures / Perpetual Trading

### 2.1 Contract size

- Futures instruments also have a `contract_size` requirement.
- The `amount` must be a multiple of `contract_size`.
- The toolkit enforces this and gives a helpful error when the amount does not conform.

### 2.2 Risk control

Recommended for tests:
- Use small sizes and short-lived positions.
- Implement an automated “buy then immediately close” round trip as part of your
  regression tests (we provide examples under `examples/`).

## 3. Options Trading

### 3.1 Typical issues we hit

#### 3.1.1 `not_enough_funds`

**Symptom** (HTTP 400):
- `code: 10009, message: "not_enough_funds"`

**Cause:**
- Options require option premium (and possibly margin).
- Some options have relatively high per-contract cost.
- A small account (e.g. ~0.02 ETH) cannot afford certain options.

**Practical lesson:**
- With limited balance, prefer options with **very small `mark_price`**
  (close to zero). For example, we successfully traded
  `ETH-19NOV25-2800-P` with `mark_price ≈ 0.0001 ETH`.

#### 3.1.2 `must conform to tick size`

**Symptom** (HTTP 400):
- `code: -32602`
- `data.reason: "must conform to tick size"`

**What we did to investigate:**
- Used `public/get_instruments` to read `tick_size`.
- Used `Decimal` to construct `price = k * tick_size` values.
- As a cross-check, we wrote a raw JSON-RPC debug script that calls
  `private/buy` directly with different prices.

**What we observed:**
- For some options, even prices that are clean multiples of `tick_size`
  still return `must conform to tick size`.
- This strongly suggests Deribit applies additional internal rules
  (price bands, step sizes, min price, etc.) beyond the public `tick_size` field.

**Conclusion:**
- In the toolkit we only do **spec-based validation** using `tick_size` and
  do not try to guess all of Deribit’s internal rules.
- If you need to explore which prices are accepted at a given moment for a
  specific option, do it via dedicated debug scripts in `examples/`, not in
  the core tooling.

### 3.2 A stable, low-risk options test pattern

Given a small balance, we found a relatively stable pattern for testing
options functionality:

1. **Automatically pick the cheapest ETH option**
   - Use `GetInstrumentsTool(currency="ETH", kind="option", expired=False)`.
   - For each instrument:
     - Use `GetTickerTool` to get `mark_price`.
     - Compute estimated per-contract cost: `est_cost = mark_price * contract_size`.
   - Filter options where `est_cost` is far below the account balance and below
     a hard cap (e.g. `0.005 ETH`), then pick the **cheapest one**.

2. **Buy using a market order with small size (1 contract)**
   - Call `PlaceBuyOrderTool` with:
     - `order_type="market"`
     - `amount=1.0` (or 1 × `contract_size`)
   - Benefits:
     - The matching engine chooses the actual fill price and handles tick-size
       and price-band constraints.
     - For extremely cheap options, the actual cost is tiny, so this is safe
       for functional verification and regression tests.
   - In our tests:
     - Buying `ETH-19NOV25-2800-P` with `amount=1.0` via a market order
       returned `order_state: "filled"`, `filled_amount: 1.0`, and
       `average_price ≈ 0.0002`.

3. **Close the position with a reduce-only market sell**
   - First, verify positions with `GetPositionsTool(currency="ETH", kind="option")`:
     - Find the option with `size > 0` (e.g. `ETH-19NOV25-2800-P size=1.0`).
   - Then call `PlaceSellOrderTool` with:
     - `order_type="market"`
     - `amount = current long size`
     - `reduce_only=True` (so it only closes the position, never opens a short)
   - This lets you complete a buy+sell round trip without worrying about the
     exact limit price.

4. **Round-trip example script**
   - The script `examples/test_options_safe_roundtrip.py` shows this pattern:
     - Automatically pick a cheap ETH option.
     - Buy 1 contract with a market order.
     - Check positions and sell the same amount with a reduce-only market order.
     - Print initial balance, final balance, PnL and recent trade history.

## 4. Boundary Conditions and Toolkit Design Philosophy

### 4.1 What the toolkit does

In `spoon_toolkits.data_platforms.deribit` we stick to a clear separation of concerns:

**The toolkit does:**
- Configuration / JSON-RPC client management / OAuth2 authentication.
- Basic parameter validation: required fields, `> 0` checks, etc.
- Spec-based validation using `get_instruments`:
  - Ensure `amount` is a multiple of `contract_size`.
  - Ensure `price` conforms to `tick_size` (for limit orders).
- When validation fails:
  - Do **not** call the API.
  - Return a structured error with a human-readable message and suggested values.

**The toolkit does not:**
- Change trade direction for you (no auto buy/sell decisions).
- Implement account-level money management (e.g. auto downsize on low balance).
- Implement price-search strategies (e.g. automatically probing different
  limit prices until Deribit accepts one).
- Decide when to close positions or convert all balances to ETH – those are
  higher-level, strategy-specific concerns.

### 4.2 Why this separation matters

- Deribit’s internal behaviour (especially around price bands and ticks for
  options) is not fully documented.
- Trying to “guess the rules” inside the core toolkit is dangerous: a future
  API change could break assumptions and turn the toolkit itself into a bug.
- By keeping **all strategies and experiments** in `examples/` and limiting
  the toolkit to spec-based validation, we get:
  - A stable, predictable API surface for other code to build on.
  - Freedom to iterate on test strategies and debugging scripts without
    risking regressions in the main package.

## 5. Recommended Usage Flow

### 5.1 First-time setup / sanity checks

1. Run `examples/test_public_api.py` and `test_authentication.py` to verify
   network connectivity and authentication.
2. Run `test_market_data_tools.py` and `test_account_tools.py` to confirm
   that market data and balances are accessible and correctly parsed.

### 5.2 Spot / futures functional tests

1. Use `test_0.02eth_safe_trading.py` or `test_spot_trading.py` to verify
   amount / contract-size validation and the basic trading tools.
2. For full workflows, look at:
   - `test_complete_trading_workflow.py`
   - `test_all_trading_types.py`

### 5.3 Options functional tests

- Use `test_options_safe_roundtrip.py` as the go-to script:
  - It will automatically select a cheap ETH option.
  - Execute a full buy+sell round trip with small risk.
  - Print balance changes and trade details.

### 5.4 When you see parameter errors

- First, look at the toolkit error message – it usually includes the
  relevant `contract_size` / `tick_size` and suggested values.
- If the error comes from Deribit itself (e.g. `not_enough_funds` or
  `must conform to tick size`):
  - Re-check balance, price bands and instrument specs.
  - When in doubt, use the debug-oriented scripts under `examples/` to
    probe the behaviour of the specific instrument.

