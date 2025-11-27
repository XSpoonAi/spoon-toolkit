"""Automatically select an affordable ETH option and attempt a real buy trade.

This script is intended for use under ``examples/`` only.
"""

import asyncio
import sys
from pathlib import Path
import importlib.util
from decimal import Decimal
from typing import Optional, Tuple

# Dynamically load deribit modules

deribit_path = Path(__file__).parent.parent
sys.path.insert(0, str(deribit_path.parent.parent.parent))


def load_module(name: str, file_path: Path):
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
PlaceBuyOrderTool = trading_module.PlaceBuyOrderTool
GetTradeHistoryTool = account_module.GetTradeHistoryTool


async def get_eth_balance() -> Optional[float]:
    """Get current ETH balance."""
    tool = GetAccountSummaryTool()
    result = await tool.execute(currency="ETH")
    if isinstance(result, dict) and result.get("error"):
        print("[ERROR] Failed to get ETH balance:", result.get("error"))
        return None
    acct = result.get("output") if isinstance(result, dict) else result
    return float(acct.get("balance", 0))


async def pick_affordable_option(max_cost_eth: float = 0.005) -> Optional[Tuple[str, float, float]]:
    """Pick the cheapest ETH option whose estimated cost <= ``max_cost_eth``.

    Returns (instrument_name, mark_price, tick_size).
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

    # Limit the number of instruments to keep requests reasonable
    instruments = instruments[:80]

    ticker_tool = GetTickerTool()
    candidates = []

    for inst in instruments:
        name = inst.get("instrument_name")
        if not name:
            continue
        tick_size = float(inst.get("tick_size", 0.0) or 0.0)
        contract_size = float(inst.get("contract_size", 1.0) or 1.0)

        # Get mark_price
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

        # Estimated cost for 1 contract
        est_cost = mark * contract_size
        if est_cost <= max_cost_eth:
            candidates.append((name, mark, tick_size, est_cost))

    if not candidates:
        print(f"[INFO] No affordable ETH options found with cost <= {max_cost_eth} ETH.")
        return None

    # Sort by cost ascending, pick the cheapest
    candidates.sort(key=lambda x: x[3])
    name, mark, tick_size, est_cost = candidates[0]

    print("[SELECTED OPTION]", name)
    print(f"  mark_price   : {mark}")
    print(f"  tick_size    : {tick_size}")
    print(f"  estimated cost (1 contract): {est_cost} ETH")

    return name, mark, tick_size


def build_market_price(mark: float) -> float:
    """Placeholder for potential future price logic; market orders do not need a price."""
    return mark


async def place_option_market_buy(instrument_name: str, amount: float) -> bool:
    """Buy an option using a market order (1 contract or specified amount)."""
    tool = PlaceBuyOrderTool()
    result = await tool.execute(
        instrument_name=instrument_name,
        amount=amount,
        order_type="market",
    )

    if isinstance(result, dict) and result.get("error"):
        print("[ERROR] Option market buy failed:")
        print(result.get("error"))
        return False

    out = result.get("output") if isinstance(result, dict) else result
    order = out.get("order") if isinstance(out, dict) else None
    if not order:
        print("[WARN] 'order' field not found in response:", out)
        return False

    print("[BUY ORDER PLACED] order:")
    print(order)
    return True


async def main():
    print("=== Auto-select an affordable ETH option and buy 1 contract (market) ===")
    balance = await get_eth_balance()
    if balance is None:
        return
    print(f"Current ETH balance: {balance:.6f} ETH")

    # Use at most 1/3 of balance for options, capped at 0.005 ETH
    max_cost = balance / 3 if balance > 0 else 0.0
    if max_cost <= 0:
        print("[ERROR] Not enough balance to buy an option.")
        return

    max_cost = min(max_cost, 0.005)
    print(f"Options test budget cap: {max_cost:.6f} ETH")

    picked = await pick_affordable_option(max_cost_eth=max_cost)
    if not picked:
        print("[END] No suitable option found within current budget.")
        return

    inst_name, mark, tick_size = picked

    # Use 1 contract (options often have contract_size = 1)
    amount = 1.0
    print(f"Preparing to market-buy 1 contract of {inst_name} (amount={amount})")

    ok = await place_option_market_buy(inst_name, amount)
    if not ok:
        print("[END] Option market buy failed.")
    else:
        print("[DONE] Market buy request sent. Please confirm fills in Deribit UI or trade history.")


if __name__ == "__main__":
    asyncio.run(main())
