"""Find the current long ETH option position (if any) and close it with a market sell.

This script is intended for use under ``examples/`` only, not as a public API.
"""

import asyncio
import sys
from pathlib import Path
import importlib.util
from typing import Optional

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

GetAccountSummaryTool = account_module.GetAccountSummaryTool
GetPositionsTool = account_module.GetPositionsTool
PlaceSellOrderTool = trading_module.PlaceSellOrderTool


async def get_eth_balance() -> Optional[float]:
    """Get current ETH balance."""
    tool = GetAccountSummaryTool()
    result = await tool.execute(currency="ETH")
    if isinstance(result, dict) and result.get("error"):
        print("[ERROR] Failed to get ETH balance:", result.get("error"))
        return None
    acct = result.get("output") if isinstance(result, dict) else result
    return float(acct.get("balance", 0))


async def pick_long_option_position() -> Optional[tuple[str, float]]:
    """Return (instrument_name, size) for a long ETH option position, or None."""
    tool = GetPositionsTool()
    result = await tool.execute(currency="ETH", kind="option")
    if isinstance(result, dict) and result.get("error"):
        print("[ERROR] Failed to fetch option positions:", result.get("error"))
        return None
    positions = result.get("output") if isinstance(result, dict) else result
    if not positions:
        print("[INFO] No ETH options positions found.")
        return None

    for pos in positions:
        size = float(pos.get("size", 0) or 0)
        inst = pos.get("instrument_name")
        if size > 0 and inst:
            print("[FOUND LONG OPTION POSITION]", inst, "size=", size)
            return inst, size

    print("[INFO] No long option positions (size>0) found.")
    return None


async def close_option_position(instrument_name: str, size: float) -> bool:
    """Close a long option position by selling ``size`` contracts at market (reduce-only)."""
    tool = PlaceSellOrderTool()
    result = await tool.execute(
        instrument_name=instrument_name,
        amount=size,
        order_type="market",
        reduce_only=True,
    )

    if isinstance(result, dict) and result.get("error"):
        print("[ERROR] Option market sell (close) failed:")
        print(result.get("error"))
        return False

    out = result.get("output") if isinstance(result, dict) else result
    order = out.get("order") if isinstance(out, dict) else None
    if not order:
        print("[WARN] 'order' field not found in response:", out)
        return False

    print("[SELL ORDER PLACED] order:")
    print(order)
    return True


async def main():
    print("=== Close current long ETH option position (if any) ===")
    balance_before = await get_eth_balance()
    if balance_before is None:
        return
    print(f"ETH balance before close: {balance_before:.6f} ETH")

    picked = await pick_long_option_position()
    if not picked:
        print("[END] No long ETH option position to close.")
        return

    inst_name, size = picked
    print(f"Attempting to close position: sell {size} {inst_name} at market (reduce_only)")

    ok = await close_option_position(inst_name, size)
    if not ok:
        print("[END] Market sell for option close failed.")
        return

    balance_after = await get_eth_balance()
    if balance_after is not None:
        print(f"ETH balance after close: {balance_after:.6f} ETH")

    print("[DONE] Please verify in Deribit UI or trade history that the option position is closed.")


if __name__ == "__main__":
    asyncio.run(main())
