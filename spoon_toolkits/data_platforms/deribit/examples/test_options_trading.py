"""Basic Options trading test script (create test limit buy/sell orders and then cancel them)."""

import asyncio
import sys
from pathlib import Path
import importlib.util
from decimal import Decimal, ROUND_DOWN, ROUND_UP

# Add deribit module directory to path
deribit_path = Path(__file__).parent.parent
sys.path.insert(0, str(deribit_path.parent.parent.parent))

def load_module(name, file_path):
    """Load a module from file path, handling relative imports"""
    full_name = f'spoon_toolkits.data_platforms.deribit.{name}'
    spec = importlib.util.spec_from_file_location(full_name, file_path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = 'spoon_toolkits.data_platforms.deribit'
    import types
    parent_pkg = 'spoon_toolkits.data_platforms.deribit'
    parts = parent_pkg.split('.')
    for i in range(len(parts)):
        pkg_name = '.'.join(parts[:i+1])
        if pkg_name not in sys.modules:
            pkg = types.ModuleType(pkg_name)
            pkg.__path__ = []
            sys.modules[pkg_name] = pkg
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module

# Load modules in dependency order
env_module = load_module('env', deribit_path / 'env.py')
jsonrpc_module = load_module('jsonrpc_client', deribit_path / 'jsonrpc_client.py')
auth_module = load_module('auth', deribit_path / 'auth.py')
base_module = load_module('base', deribit_path / 'base.py')
market_module = load_module('market_data', deribit_path / 'market_data.py')
trading_module = load_module('trading', deribit_path / 'trading.py')

GetInstrumentsTool = market_module.GetInstrumentsTool
GetTickerTool = market_module.GetTickerTool
PlaceBuyOrderTool = trading_module.PlaceBuyOrderTool
PlaceSellOrderTool = trading_module.PlaceSellOrderTool
CancelOrderTool = trading_module.CancelOrderTool

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text:^70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}\n")

def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")

def print_error(text):
    print(f"{Colors.RED}❌ {text}{Colors.RESET}")

def print_info(text):
    print(f"{Colors.CYAN}ℹ️  {text}{Colors.RESET}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")

async def find_available_options():
    """Find an available ETH options instrument to use in the test."""
    print_header("STEP 1: Find available options instrument")
    
    tool = GetInstrumentsTool()
    
    # Query ETH options instruments
    print_info("Querying ETH options instruments...")
    result_eth = await tool.execute(currency="ETH", kind="option", expired=False)
    
    if isinstance(result_eth, dict) and result_eth.get("error"):
        print_error(f"Query failed: {result_eth.get('error')}")
        return None, None, None
    
    instruments_eth = result_eth.get("output") if isinstance(result_eth, dict) else result_eth
    
    if not instruments_eth:
        print_warning("No ETH options instruments found")
        return None, None, None
    
    # Prefer a call option, fall back to a put option
    call_option = None
    put_option = None
    
    for inst in instruments_eth:
        inst_name = inst.get("instrument_name", "")
        if inst_name.endswith("-C") and not call_option:
            call_option = inst
        elif inst_name.endswith("-P") and not put_option:
            put_option = inst
    
    if call_option:
        print_success(f"Found call option: {call_option.get('instrument_name')}")
        print_info(f"  contract_size      : {call_option.get('contract_size', 'N/A')}")
        print_info(f"  min_trade_amount   : {call_option.get('min_trade_amount', 'N/A')}")
        print_info(f"  price tick_size    : {call_option.get('tick_size', 'N/A')}")
    
    if put_option:
        print_success(f"Found put option: {put_option.get('instrument_name')}")
        print_info(f"  contract_size      : {put_option.get('contract_size', 'N/A')}")
        print_info(f"  min_trade_amount   : {put_option.get('min_trade_amount', 'N/A')}")
        print_info(f"  price tick_size    : {put_option.get('tick_size', 'N/A')}")
    
    # Prefer a call option, fall back to a put option
    selected_option = call_option if call_option else put_option
    
    if selected_option:
        return (
            selected_option.get("instrument_name"),
            selected_option.get("contract_size"),
            selected_option.get("tick_size")
        )
    
    return None, None, None

async def test_options_buy(option_name: str, contract_size: float, tick_size: float = None):
    """Create a limit buy order for the selected option (deep out-of-the-money; should not fill)."""
    print_header("STEP 2: Options buy test")
    
    # Use minimal trade unit (1×contract_size when available)
    amount = contract_size if contract_size and contract_size > 0 else 0.01
    
    print_info(f"Instrument : {option_name}")
    print_info(f"Buy amount : {amount} (1×contract_size)")
    print_warning("⚠️  Using a deep limit order at 50% below market; this should not fill.")
    
    # Fetch current price and tick_size
    ticker_tool = GetTickerTool()
    ticker_result = await ticker_tool.execute(instrument_name=option_name)
    
    current_price = None
    if isinstance(ticker_result, dict) and not ticker_result.get("error"):
        ticker = ticker_result.get("output", {})
        current_price = ticker.get("last_price") or ticker.get("mark_price")
        if not tick_size:
            tick_size = ticker.get("tick_size", 0.0001)
    
    if not tick_size:
        tick_size = 0.0001  # default tick_size fallback
    
    if current_price:
        print_info(f"Current price: ${current_price:,.4f}")
        print_info(f"Price tick_size: {tick_size}")
        # Use Decimal for precise arithmetic
        price_decimal = Decimal(str(current_price))
        tick_decimal = Decimal(str(tick_size))
        limit_price_raw = price_decimal * Decimal('0.5')
        # Round down to a multiple of tick_size
        limit_price = (limit_price_raw / tick_decimal).quantize(Decimal('1'), rounding=ROUND_DOWN) * tick_decimal
        # Ensure price is at least one tick
        if limit_price < tick_decimal:
            limit_price = tick_decimal
        limit_price = float(limit_price)
        print_info(f"Limit price: ${limit_price:,.4f} (deep, should not fill)")
    else:
        print_warning("Unable to fetch current price; using default limit price based on tick_size")
        tick_decimal = Decimal(str(tick_size))
        limit_price = float(tick_decimal)
    
    # Create buy order
    buy_tool = PlaceBuyOrderTool()
    result = await buy_tool.execute(
        instrument_name=option_name,
        amount=amount,
        price=limit_price,
        order_type="limit"
    )
    
    if isinstance(result, dict) and result.get("error"):
        print_error(f"Buy order failed: {result.get('error')}")
        return None
    
    order = result.get("output", {}).get("order", {}) if isinstance(result, dict) else result.get("order", {})
    order_id = order.get("order_id")
    
    if order_id:
        print_success(f"Buy order created: {order_id}")
        print_info(f"  order_state: {order.get('order_state', 'N/A')}")
        print_info(f"  amount     : {order.get('amount', 'N/A')}")
        print_info(
            f"  price      : ${order.get('price', 'N/A'):,.2f}"
            if order.get('price')
            else "  price      : N/A"
        )
        return order_id
    
    return None

async def test_options_sell(option_name: str, contract_size: float, tick_size: float = None):
    """Create a limit sell order for the selected option (deep above market; should not fill)."""
    print_header("STEP 3: Options sell test")
    
    # Use minimal trade unit (1×contract_size when available)
    amount = contract_size if contract_size and contract_size > 0 else 0.01
    
    print_info(f"Instrument : {option_name}")
    print_info(f"Sell amount: {amount} (1×contract_size)")
    print_warning("⚠️  Using a limit order 50% above market; this should not fill.")
    
    # Fetch current price and tick_size
    ticker_tool = GetTickerTool()
    ticker_result = await ticker_tool.execute(instrument_name=option_name)
    
    current_price = None
    if isinstance(ticker_result, dict) and not ticker_result.get("error"):
        ticker = ticker_result.get("output", {})
        current_price = ticker.get("last_price") or ticker.get("mark_price")
        if not tick_size:
            tick_size = ticker.get("tick_size", 0.0001)
    
    if not tick_size:
        tick_size = 0.0001  # default tick_size fallback
    
    if current_price:
        print_info(f"Current price: ${current_price:,.4f}")
        print_info(f"Price tick_size: {tick_size}")
        # Use Decimal for precise arithmetic
        price_decimal = Decimal(str(current_price))
        tick_decimal = Decimal(str(tick_size))
        limit_price_raw = price_decimal * Decimal('1.5')
        # Round up to a multiple of tick_size
        limit_price = (limit_price_raw / tick_decimal).quantize(Decimal('1'), rounding=ROUND_UP) * tick_decimal
        limit_price = float(limit_price)
        print_info(f"Limit price: ${limit_price:,.4f} (deep, should not fill)")
    else:
        print_warning("Unable to fetch current price; using default high limit price")
        tick_decimal = Decimal(str(tick_size))
        # Fallback to an arbitrarily high price far above typical market levels.
        limit_price = float(tick_decimal * Decimal("1000"))
    
    # Create sell order
    sell_tool = PlaceSellOrderTool()
    result = await sell_tool.execute(
        instrument_name=option_name,
        amount=amount,
        price=limit_price,
        order_type="limit"
    )
    
    if isinstance(result, dict) and result.get("error"):
        print_error(f"Sell order failed: {result.get('error')}")
        return None
    
    order = result.get("output", {}).get("order", {}) if isinstance(result, dict) else result.get("order", {})
    order_id = order.get("order_id")
    
    if order_id:
        print_success(f"Sell order created: {order_id}")
        print_info(f"  order_state: {order.get('order_state', 'N/A')}")
        print_info(f"  amount     : {order.get('amount', 'N/A')}")
        print_info(
            f"  price      : ${order.get('price', 'N/A'):,.2f}"
            if order.get('price')
            else "  price      : N/A"
        )
        return order_id
    
    return None

async def cancel_order(order_id: str):
    """Cancel a single order by ID."""
    if not order_id:
        return
    
    print_info(f"Cancelling order: {order_id}")
    cancel_tool = CancelOrderTool()
    result = await cancel_tool.execute(order_id=order_id)
    
    if isinstance(result, dict) and result.get("error"):
        print_error(f"Cancel failed: {result.get('error')}")
    else:
        print_success(f"Order cancelled: {order_id}")

async def main():
    """Entry point for the basic options limit-order test."""
    print_header("Options trading test (limit orders, non-filling)")
    
    print_warning("⚠️  This test creates real limit orders, far away from market price.")
    print_warning("⚠️  All created orders will be cancelled before the script exits.")
    
    # STEP 1: Find an options instrument
    option_name, contract_size, tick_size = await find_available_options()
    
    if not option_name:
        print_error("No suitable options instrument found; aborting test")
        return
    
    await asyncio.sleep(1)
    
    # STEP 2: Test limit buy
    buy_order_id = await test_options_buy(option_name, contract_size, tick_size)
    
    await asyncio.sleep(2)
    
    # STEP 3: Test limit sell
    print_warning("⚠️  Selling the option requires an open position; otherwise the sell may fail.")
    sell_order_id = await test_options_sell(option_name, contract_size, tick_size)
    
    await asyncio.sleep(2)
    
    # STEP 4: Cleanup
    print_header("STEP 4: Cleanup (cancel any created orders)")
    
    if buy_order_id:
        await cancel_order(buy_order_id)
        await asyncio.sleep(1)
    
    if sell_order_id:
        await cancel_order(sell_order_id)
        await asyncio.sleep(1)
    
    # Summary
    print_header("Test summary")
    print_success("Options trading limit-order test completed.")
    print_info(f"Tested instrument: {option_name}")
    if buy_order_id:
        print_success(f"Buy order ID : {buy_order_id} ✅")
    if sell_order_id:
        print_success(f"Sell order ID: {sell_order_id} ✅")

if __name__ == "__main__":
    asyncio.run(main())

