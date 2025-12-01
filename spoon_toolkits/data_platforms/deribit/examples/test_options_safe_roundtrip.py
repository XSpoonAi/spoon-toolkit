"""Safe options round-trip test.

This example:
- Runs only under ``examples/`` (not part of the public API surface).
- Strategy:
  1. Query all ETH options and pick the cheapest one by ``mark_price * contract_size``;
  2. Buy 1 contract using a market order;
  3. Verify the resulting long position;
  4. Sell the same amount using a reduce-only market order to close the position;
  5. Print initial balance, final balance, PnL, and recent trades.
"""

import asyncio
import sys
from pathlib import Path
import importlib.util
from decimal import Decimal
from typing import Optional, Tuple, List, Dict

# Dynamically load deribit modules (same pattern as test_options_complete.py)
deribit_path = Path(__file__).parent.parent
sys.path.insert(0, str(deribit_path.parent.parent.parent))


def load_module(name: str, file_path: Path):
    """Load a module from file path, handling relative imports"""
    full_name = f"spoon_toolkits.data_platforms.deribit.{name}"
    spec = importlib.util.spec_from_file_location(full_name, file_path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "spoon_toolkits.data_platforms.deribit"
    import types
    parent_pkg = "spoon_toolkits.data_platforms.deribit"
    parts = parent_pkg.split(".")
    for i in range(len(parts)):
        pkg_name = ".".join(parts[: i + 1])
        if pkg_name not in sys.modules:
            pkg = types.ModuleType(pkg_name)
            pkg.__path__ = []
            sys.modules[pkg_name] = pkg
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


# Load modules in dependency order
env_module = load_module("env", deribit_path / "env.py")
jsonrpc_module = load_module("jsonrpc_client", deribit_path / "jsonrpc_client.py")
auth_module = load_module("auth", deribit_path / "auth.py")
base_module = load_module("base", deribit_path / "base.py")
market_module = load_module("market_data", deribit_path / "market_data.py")
account_module = load_module("account", deribit_path / "account.py")
trading_module = load_module("trading", deribit_path / "trading.py")

DeribitConfig = env_module.DeribitConfig
GetInstrumentsTool = market_module.GetInstrumentsTool
GetTickerTool = market_module.GetTickerTool
GetAccountSummaryTool = account_module.GetAccountSummaryTool
GetPositionsTool = account_module.GetPositionsTool
GetTradeHistoryTool = account_module.GetTradeHistoryTool
PlaceBuyOrderTool = trading_module.PlaceBuyOrderTool
PlaceSellOrderTool = trading_module.PlaceSellOrderTool


async def get_eth_balance() -> Optional[float]:
    tool = GetAccountSummaryTool()
    result = await tool.execute(currency="ETH")
    if isinstance(result, dict) and result.get("error"):
        print("[ERROR] Failed to get ETH balance:", result.get("error"))
        return None
    acct = result.get("output") if isinstance(result, dict) else result
    return float(acct.get("balance", 0))


async def pick_cheapest_eth_option(max_cost_eth: float) -> Optional[Tuple[str, float, float, float]]:
    """Pick the cheapest ETH option whose estimated cost <= ``max_cost_eth``.

    Returns (instrument_name, mark_price, tick_size, est_cost_eth).
    """
    inst_tool = GetInstrumentsTool()
    result = await inst_tool.execute(currency="ETH", kind="option", expired=False)
    if isinstance(result, dict) and result.get("error"):
        print("[ERROR] Failed to fetch options instruments:", result.get("error"))
        return None

    instruments = result.get("output") if isinstance(result, dict) else result
    if not instruments:
        print("[ERROR] No ETH options instruments found")
        return None

    # Limit the number of instruments checked to keep requests reasonable
    instruments = instruments[:100]

    ticker_tool = GetTickerTool()
    candidates: List[Tuple[str, float, float, float]] = []

    for inst in instruments:
        name = inst.get("instrument_name")
        if not name:
            continue
        tick_size = float(inst.get("tick_size", 0.0) or 0.0)
        contract_size = float(inst.get("contract_size", 1.0) or 1.0)

        t_res = await ticker_tool.execute(instrument_name=name)
        if isinstance(t_res, dict) and t_res.get("error"):
            continue
        ticker = t_res.get("output") if isinstance(t_res, dict) else t_res
        mark = ticker.get("mark_price") or ticker.get("last_price")
        if not mark:
            continue
        mark = float(mark)
        if mark <= 0:
            continue

        est_cost = mark * contract_size
        if est_cost <= max_cost_eth:
            candidates.append((name, mark, tick_size, est_cost))

    if not candidates:
        print(f"[INFO] No affordable ETH options found with cost <= {max_cost_eth} ETH.")
        return None

    candidates.sort(key=lambda x: x[3])
    name, mark, tick_size, est_cost = candidates[0]

    print("[SELECTED OPTION]", name)
    print(f"  mark_price   : {mark}")
    print(f"  tick_size    : {tick_size}")
    print(f"  estimated cost (1 contract): {est_cost} ETH")

    return name, mark, tick_size, est_cost


async def place_option_market_buy(instrument_name: str, amount: float) -> Optional[Dict]:
    """Place a market buy order for an option. Returns the ``order`` dict if successful."""
    tool = PlaceBuyOrderTool()
    result = await tool.execute(
        instrument_name=instrument_name,
        amount=amount,
        order_type="market",
    )

    if isinstance(result, dict) and result.get("error"):
        print("[ERROR] Option market buy failed:")
        print(result.get("error"))
        return None

    out = result.get("output") if isinstance(result, dict) else result
    order = out.get("order") if isinstance(out, dict) else None
    if not order:
        print("[WARN] 'order' field not found in response:", out)
        return None

    print("[BUY ORDER PLACED] order:")
    print(order)
    return order


async def place_option_market_sell(instrument_name: str, amount: float) -> Optional[Dict]:
    """Place a reduce-only market sell order to close a long option position."""
    tool = PlaceSellOrderTool()
    result = await tool.execute(
        instrument_name=instrument_name,
        amount=amount,
        order_type="market",
        reduce_only=True,
    )

    if isinstance(result, dict) and result.get("error"):
        print("[ERROR] Option market sell (close) failed:")
        print(result.get("error"))
        return None

    out = result.get("output") if isinstance(result, dict) else result
    order = out.get("order") if isinstance(out, dict) else None
    if not order:
        print("[WARN] 'order' field not found in response:", out)
        return None

    print("[SELL ORDER PLACED] order:")
    print(order)
    return order


async def get_option_long_position(instrument_name: str) -> float:
    """Return the long position size (>0) for the given option, or 0.0 if none."""
    tool = GetPositionsTool()
    result = await tool.execute(currency="ETH", kind="option")
    positions = result.get("output") if isinstance(result, dict) else result
    if not positions:
        return 0.0
    for pos in positions:
        if pos.get("instrument_name") == instrument_name:
            return float(pos.get("size", 0) or 0)
    return 0.0


async def print_recent_trades(instrument_name: str, label: str):
    """Print a few recent trades for the given option."""
    tool = GetTradeHistoryTool()
    result = await tool.execute(instrument_name=instrument_name, count=5)
    if isinstance(result, dict) and result.get("error"):
        print(f"[{label}] Failed to fetch trade history:", result.get("error"))
        return
    trades = result.get("output") if isinstance(result, dict) else result
    if not trades:
        print(f"[{label}] No trades found.")
        return
    print(f"[{label}] Recent trades:")
    for t in trades:
        direction = t.get("direction")
        amount = t.get("amount")
        price = t.get("price")
        fee = t.get("fee")
        print(f"  {direction} {amount} @ {price}, fee={fee}")


async def run_safe_roundtrip():
    print("=== Options safe round-trip: buy + sell 1 ETH option ===")

    initial_balance = await get_eth_balance()
    if initial_balance is None:
        return
    print(f"Initial ETH balance: {initial_balance:.6f} ETH")

    # Budget: use at most 1/3 of the balance, capped at 0.005 ETH
    max_cost = initial_balance / 3 if initial_balance > 0 else 0.0
    max_cost = min(max_cost, 0.005)
    if max_cost <= 0:
        print("[ERROR] Not enough balance to run options test.")
        return
    print(f"Options budget cap: {max_cost:.6f} ETH")

    picked = await pick_cheapest_eth_option(max_cost_eth=max_cost)
    if not picked:
        print("[END] No suitable option found within budget.")
        return

    inst_name, mark, tick_size, est_cost = picked

    # Buy 1 contract
    amount = 1.0
    print(f"\n[STEP 1] Market buy {amount} {inst_name}")
    buy_order = await place_option_market_buy(inst_name, amount)
    if not buy_order:
        print("[END] Buy failed, stopping test.")
        return

    await asyncio.sleep(2)
    await print_recent_trades(inst_name, "AFTER BUY")

    # Confirm position
    pos_size = await get_option_long_position(inst_name)
    print(f"Current position: {inst_name} size={pos_size}")
    
    # Sell to close
    print(f"\n[STEP 2] Market sell {amount} {inst_name} (reduce_only close)")
    sell_order = await place_option_market_sell(inst_name, amount)
    if not sell_order:
        print("[END] Sell failed, stopping test.")
        return

    await asyncio.sleep(2)
    await print_recent_trades(inst_name, "AFTER SELL")
    
    # Check position again
    pos_size_after = await get_option_long_position(inst_name)
    print(f"Position after close: {inst_name} size={pos_size_after}")
    
    # Balance and PnL
    final_balance = await get_eth_balance()
    if final_balance is None:
        return
    print(f"Final ETH balance: {final_balance:.6f} ETH")
    pnl = final_balance - initial_balance
    print(f"Options round-trip PnL: {pnl:.6f} ETH")


async def main():
    await run_safe_roundtrip()


if __name__ == "__main__":
    asyncio.run(main())
