"""Deribit complete trading workflow test – spot + futures.

This script performs a small, end-to-end workflow on Deribit:
1) Spot sell ETH -> USDC and buy back ETH
2) Futures buy then sell to close
3) Cleanup all open orders and verify balances/positions
It is designed as a developer-facing integration test with real trades.
"""

import asyncio
import sys
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List

# Add deribit module directory to path
deribit_path = Path(__file__).parent.parent
sys.path.insert(0, str(deribit_path.parent.parent.parent))

# Import using importlib.util to handle relative imports
import importlib.util

def load_module(name, file_path):
    """Load a module from file path, handling relative imports"""
    full_name = f'spoon_toolkits.data_platforms.deribit.{name}'
    spec = importlib.util.spec_from_file_location(full_name, file_path)
    module = importlib.util.module_from_spec(spec)
    # Set __package__ for relative imports
    module.__package__ = 'spoon_toolkits.data_platforms.deribit'
    # Add parent packages to sys.modules for relative imports
    parent_pkg = 'spoon_toolkits.data_platforms.deribit'
    import types
    parts = parent_pkg.split('.')
    for i in range(len(parts)):
        pkg_name = '.'.join(parts[:i+1])
        if pkg_name not in sys.modules:
            pkg = types.ModuleType(pkg_name)
            pkg.__path__ = []
            sys.modules[pkg_name] = pkg
    # Register module in sys.modules
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module

# Load modules in dependency order
# First load env (no dependencies)
env_module = load_module('env', deribit_path / 'env.py')
# Then load jsonrpc_client (depends on env)
jsonrpc_module = load_module('jsonrpc_client', deribit_path / 'jsonrpc_client.py')
# Then load auth (depends on jsonrpc_client and env)
auth_module = load_module('auth', deribit_path / 'auth.py')
# Then load base (depends on jsonrpc_client and auth)
base_module = load_module('base', deribit_path / 'base.py')
# Then load tools that depend on base
market_module = load_module('market_data', deribit_path / 'market_data.py')
account_module = load_module('account', deribit_path / 'account.py')
trading_module = load_module('trading', deribit_path / 'trading.py')

DeribitConfig = env_module.DeribitConfig
GetInstrumentsTool = market_module.GetInstrumentsTool
GetTickerTool = market_module.GetTickerTool
GetAccountSummaryTool = account_module.GetAccountSummaryTool
GetPositionsTool = account_module.GetPositionsTool
GetOrderHistoryTool = account_module.GetOrderHistoryTool
GetTradeHistoryTool = account_module.GetTradeHistoryTool
PlaceBuyOrderTool = trading_module.PlaceBuyOrderTool
PlaceSellOrderTool = trading_module.PlaceSellOrderTool
CancelOrderTool = trading_module.CancelOrderTool
CancelAllOrdersTool = trading_module.CancelAllOrdersTool
GetOpenOrdersTool = trading_module.GetOpenOrdersTool


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class TradingWorkflowTest:
    """End-to-end trading workflow test (spot + futures)."""
    
    def __init__(self):
        self.initial_eth_balance = None
        self.final_eth_balance = None
        self.eth_consumed = 0.0
        # Track all created order IDs in this workflow.
        self.created_orders: List[str] = []
        # Selected spot instrument (e.g. ETH/USDC).
        self.spot_pair = None
        # Contract size for the selected spot instrument, if any.
        self.spot_contract_size = None
        self.futures_pair = "ETH-PERPETUAL"
        # All trade records captured during the workflow.
        self.trade_records: List[Dict] = []
        # Create log file in a local logs directory.
        log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = log_dir / f"trading_log_{timestamp}.json"
        
    def print_header(self, text: str):
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{text:^70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    def print_success(self, text: str):
        print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")
    
    def print_error(self, text: str):
        print(f"{Colors.RED}❌ {text}{Colors.RESET}")
    
    def print_warning(self, text: str):
        print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")
    
    def print_info(self, text: str):
        print(f"{Colors.CYAN}ℹ️  {text}{Colors.RESET}")
    
    def print_section(self, text: str):
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'─'*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{text}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'─'*70}{Colors.RESET}\n")
    
    async def get_account_balance(self, currency: str = "ETH") -> Optional[float]:
        """Get account balance for the given currency."""
        try:
            account_tool = GetAccountSummaryTool()
            result = await account_tool.execute(currency=currency)
            
            if isinstance(result, dict) and result.get("error"):
                self.print_error(f"Failed to get account balance: {result.get('error')}")
                return None
            
            account = result.get("output") if isinstance(result, dict) else result
            balance = account.get("balance", 0)
            return float(balance)
        except Exception as e:
            self.print_error(f"Exception while getting account balance: {e}")
            return None
    
    async def find_spot_pair(self) -> Optional[str]:
        """Find a suitable spot trading pair (prefer ETH/USDC or ETH/USDT)."""
        try:
            tool = GetInstrumentsTool()
            result = await tool.execute(currency="ETH", kind="spot", expired=False)
            
            if isinstance(result, dict) and result.get("error"):
                self.print_error(f"Failed to query spot instruments: {result.get('error')}")
                return None
            
            instruments = result.get("output") if isinstance(result, dict) else result
            
            if not instruments:
                self.print_error("No ETH spot instruments found")
                return None
            
            # Prefer ETH/USDC or ETH/USDT, and remember contract_size if available.
            for inst in instruments:
                inst_name = inst.get("instrument_name", "")
                if "USDC" in inst_name or "USDT" in inst_name:
                    # Save contract_size for later adjustment.
                    contract_size = inst.get("contract_size")
                    if contract_size:
                        self.spot_contract_size = contract_size
                        self.print_info(f"Spot contract_size: {contract_size} ETH")
                    return inst_name
            
            # If no preferred pair is found, fall back to the first instrument.
            first_inst = instruments[0]
            inst_name = first_inst.get("instrument_name")
            contract_size = first_inst.get("contract_size")
            if contract_size:
                self.spot_contract_size = contract_size
                self.print_info(f"Spot contract_size: {contract_size} ETH")
            return inst_name
        except Exception as e:
            self.print_error(f"Exception while finding spot instrument: {e}")
            return None
    
    def adjust_amount_to_contract_size(self, amount: float, contract_size: float) -> float:
        """Adjust amount to be a multiple of contract_size."""
        if contract_size <= 0:
            return amount
        
        # Calculate the nearest integer multiple.
        multiple = round(amount / contract_size)
        
        # Ensure at least 1×contract_size.
        if multiple < 1:
            multiple = 1
        
        # Compute adjusted amount and handle float precision.
        adjusted_amount = multiple * contract_size
        
        # Determine decimal precision from contract_size.
        contract_size_str = str(contract_size)
        if '.' in contract_size_str:
            decimals = len(contract_size_str.split('.')[1])
        else:
            decimals = 0
        
        # Round to the correct precision.
        adjusted_amount = round(adjusted_amount, decimals)
        
        return adjusted_amount
    
    async def get_market_price(self, instrument_name: str) -> Optional[float]:
        """Get the last/mark price for an instrument."""
        try:
            ticker_tool = GetTickerTool()
            result = await ticker_tool.execute(instrument_name=instrument_name)
            
            if isinstance(result, dict) and result.get("error"):
                self.print_error(f"Failed to get price: {result.get('error')}")
                return None
            
            ticker = result.get("output") if isinstance(result, dict) else result
            price = ticker.get("last_price") or ticker.get("mark_price")
            return float(price) if price else None
        except Exception as e:
            self.print_error(f"Exception while getting price: {e}")
            return None
    
    async def place_market_order(self, instrument_name: str, amount: float, side: str) -> Optional[str]:
        """Create a market order (for quick fill, used in this workflow test)."""
        try:
            if side == "buy":
                tool = PlaceBuyOrderTool()
            else:
                tool = PlaceSellOrderTool()
            
            # Use a market order so the trade fills immediately.
            result = await tool.execute(
                instrument_name=instrument_name,
                amount=amount,
                order_type="market"
            )
            
            if isinstance(result, dict) and result.get("error"):
                error_msg = result.get("error", "Unknown error")
                self.print_error(f"{side.upper()} order failed: {error_msg}")
                # Log failed trade attempt
                await self.log_failed_trade(instrument_name, side, amount, error_msg)
                return None
            
            order_info = result.get("output", {}).get("order", {}) if isinstance(result, dict) else result.get("order", {})
            order_id = order_info.get("order_id")
            
            if order_id:
                self.created_orders.append(order_id)
                # Wait and then query trade/order history for this order.
                await asyncio.sleep(2)  # wait for fills
                await self.query_and_log_trade(instrument_name, order_id, side, amount)
                return order_id
            else:
                # Order creation failed but there was no explicit error message.
                await self.log_failed_trade(instrument_name, side, amount, "Order ID not found in response")
                return None
        except Exception as e:
            error_msg = str(e)
            self.print_error(f"Exception while creating {side} order: {error_msg}")
            # Log failed trade attempt
            await self.log_failed_trade(instrument_name, side, amount, f"Exception: {error_msg}")
            return None
    
    async def query_and_log_trade(self, instrument_name: str, order_id: str, side: str, amount: float):
        """Query and log trade/order history for a specific order."""
        try:
            self.print_info(f"Querying order/trade history for order {order_id}...")
            
            # Query order history
            order_history_tool = GetOrderHistoryTool()
            order_result = await order_history_tool.execute(
                instrument_name=instrument_name,
                count=10,
                offset=0
            )
            
            # Query trade history
            trade_history_tool = GetTradeHistoryTool()
            trade_result = await trade_history_tool.execute(
                instrument_name=instrument_name,
                count=10,
                offset=0
            )
            
            # Find matching order and an associated trade (if any)
            order_data = None
            trade_data = None
            
            if isinstance(order_result, dict) and not order_result.get("error"):
                orders = order_result.get("output", [])
                for order in orders:
                    if order.get("order_id") == order_id:
                        order_data = order
                        break
            
            if isinstance(trade_result, dict) and not trade_result.get("error"):
                trades = trade_result.get("output", [])
                # Ensure trades is a list of dicts.
                if isinstance(trades, list) and trades:
                    # Prefer a trade whose timestamp is after order creation.
                    order_time = order_data.get("creation_timestamp") if order_data else None
                    for trade in trades:
                        if not isinstance(trade, dict):
                            continue
                        trade_time = trade.get("timestamp")
                        if order_time and trade_time and trade_time >= order_time:
                            trade_data = trade
                            break
                    # If none matched, fall back to the first valid trade entry.
                    if not trade_data and trades:
                        for trade in trades:
                            if isinstance(trade, dict):
                                trade_data = trade
                                break
            
            # Build trade record
            trade_record = {
                "timestamp": datetime.now().isoformat(),
                "order_id": order_id,
                "instrument_name": instrument_name,
                "side": side,
                "amount": amount,
                "order_data": order_data,
                "trade_data": trade_data
            }
            
            self.trade_records.append(trade_record)
            
            # Print a human-readable summary to stdout.
            self.print_section(f"Trade record - {side.upper()} {instrument_name}")
            
            if order_data:
                self.print_info(f"Order ID      : {order_data.get('order_id')}")
                self.print_info(f"Order state   : {order_data.get('order_state', 'N/A')}")
                self.print_info(f"Order type    : {order_data.get('order_type', 'N/A')}")
                self.print_info(f"Amount        : {order_data.get('amount', 'N/A')}")
                self.print_info(f"Price         : {order_data.get('price', 'N/A')}")
                self.print_info(f"Created at    : {order_data.get('creation_timestamp', 'N/A')}")
                if order_data.get('last_update_timestamp'):
                    self.print_info(f"Last updated  : {order_data.get('last_update_timestamp')}")
            
            if trade_data:
                self.print_success("✅ Matched trade:")
                self.print_info(f"  trade_id : {trade_data.get('trade_id', 'N/A')}")
                self.print_info(f"  price    : {trade_data.get('price', 'N/A')}")
                self.print_info(f"  amount   : {trade_data.get('amount', 'N/A')}")
                self.print_info(f"  side     : {trade_data.get('direction', 'N/A')}")
                self.print_info(f"  ts       : {trade_data.get('timestamp', 'N/A')}")
                if trade_data.get('fee'):
                    self.print_info(f"  fee      : {trade_data.get('fee')}")
            else:
                self.print_warning("⚠️  No matching trade record found (order may not be filled).")
            
            # Persist to JSON log.
            await self.write_trade_log(trade_record)
            
        except Exception as e:
            self.print_error(f"Exception while querying trade record: {e}")
            import traceback
            traceback.print_exc()
    
    async def log_failed_trade(self, instrument_name: str, side: str, amount: float, error_msg: str):
        """Record a failed trade attempt and append it to the JSON log."""
        try:
            failed_record = {
                "timestamp": datetime.now().isoformat(),
                "order_id": None,
                "instrument_name": instrument_name,
                "side": side,
                "amount": amount,
                "status": "failed",
                "error": error_msg,
                "order_data": None,
                "trade_data": None
            }
            
            self.trade_records.append(failed_record)
            
            # Print a short failure summary
            self.print_section(f"Trade record - {side.upper()} {instrument_name} (FAILED)")
            self.print_error("Order creation failed")
            self.print_error(f"Error: {error_msg}")
            self.print_info(f"Instrument: {instrument_name}")
            self.print_info(f"Side      : {side.upper()}")
            self.print_info(f"Amount    : {amount}")
            
            # Persist to JSON log
            await self.write_trade_log(failed_record)
            
        except Exception as e:
            self.print_error(f"Exception while recording failed trade: {e}")
    
    async def write_trade_log(self, trade_record: Dict):
        """Append a single trade_record dict into the JSON log file."""
        try:
            # Load existing log data (if any)
            log_data = []
            if self.log_file.exists():
                try:
                    with open(self.log_file, 'r', encoding='utf-8') as f:
                        log_data = json.load(f)
                except Exception:
                    log_data = []
            else:
                log_data = []
            
            # Append new record and write back
            log_data.append(trade_record)
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump(log_data, f, indent=2, ensure_ascii=False)
            
            self.print_info(f"Trade record written to: {self.log_file}")
            
        except Exception as e:
            self.print_error(f"Exception while writing JSON log: {e}")
    
    async def cancel_all_orders(self, instrument_name: str):
        """Cancel all open orders for the specified instrument's currency/kind."""
        try:
            # CancelAllOrdersTool needs currency and kind, not instrument_name.
            # Extract currency/kind from the instrument_name string.
            currency = None
            kind = None
            
            if instrument_name:
                # Parse instrument_name, e.g.:
                # "ETH-PERPETUAL" -> currency="ETH", kind="future"
                # "ETH-USDC"      -> currency="ETH", kind="spot"
                if "PERPETUAL" in instrument_name or "-" in instrument_name and len(instrument_name.split("-")) == 3:
                    # Perpetual or dated future, e.g. "ETH-PERPETUAL" or "BTC-25JAN25"
                    currency = instrument_name.split("-")[0]
                    kind = "future"
                elif "-" in instrument_name:
                    # Spot instrument, e.g. "ETH-USDC"
                    currency = instrument_name.split("-")[0]
                    kind = "spot"
                else:
                    # Fallback to ETH when currency cannot be parsed
                    currency = "ETH"
                    kind = "any"
            
            if not currency:
                self.print_warning(f"Unable to infer currency from {instrument_name}; skipping cancel_all")
                return False
            
            cancel_tool = CancelAllOrdersTool()
            result = await cancel_tool.execute(currency=currency, kind=kind if kind != "any" else "any")
            
            if isinstance(result, dict) and result.get("error"):
                self.print_warning(f"CancelAllOrdersTool failed: {result.get('error')}")
                return False
            
            self.print_success(f"Cancelled all orders for {instrument_name} ({currency}, {kind})")
            return True
        except Exception as e:
            self.print_error(f"Exception while cancelling all orders: {e}")
            return False
    
    async def verify_no_open_orders(self):
        """Verify that there are no open spot/futures orders."""
        try:
            # Check spot orders
            if self.spot_pair:
                orders_tool = GetOpenOrdersTool()
                spot_result = await orders_tool.execute(instrument_name=self.spot_pair)
                spot_orders = spot_result.get("output") if isinstance(spot_result, dict) else spot_result
                if spot_orders:
                    self.print_warning(f"Found {len(spot_orders)} open spot orders")
                    return False
            
            # Check futures orders
            orders_tool = GetOpenOrdersTool()
            futures_result = await orders_tool.execute(instrument_name=self.futures_pair)
            futures_orders = futures_result.get("output") if isinstance(futures_result, dict) else futures_result
            if futures_orders:
                self.print_warning(f"Found {len(futures_orders)} open futures orders")
                return False
            
            self.print_success("Confirmed there are no open spot/futures orders")
            return True
        except Exception as e:
            self.print_error(f"Exception while verifying open orders: {e}")
            return False
    
    async def test_spot_sell(self, eth_amount: float) -> bool:
        """Test 1: spot sell leg ETH -> USDC."""
        self.print_section("TEST 1: Spot sell ETH -> USDC")
        
        if not self.spot_pair:
            self.print_error("No spot pair found; skipping spot test")
            return False
        
        price = await self.get_market_price(self.spot_pair)
        if not price:
            return False
        
        # Adjust amount to contract_size, if defined.
        if self.spot_contract_size:
            original_amount = eth_amount
            eth_amount = self.adjust_amount_to_contract_size(eth_amount, self.spot_contract_size)
            if abs(eth_amount - original_amount) > 0.0001:
                self.print_warning(
                    f"Adjusted amount: {original_amount:.6f} -> {eth_amount:.6f} ETH (multiple of contract_size)"
                )
        
        self.print_info(f"Current price: ${price:,.2f}")
        self.print_info(f"Sell amount  : {eth_amount} ETH")
        self.print_warning("⚠️  Using market orders; trades will fill immediately.")
        
        order_id = await self.place_market_order(self.spot_pair, eth_amount, "sell")
        if not order_id:
            return False
        
        self.print_success(f"Spot sell order created: {order_id}")
        await asyncio.sleep(2)  # wait for fills
        
        return True
    
    async def test_spot_buy(self, usdc_amount: float) -> bool:
        """Test 2: spot buy leg ETH <- USDC."""
        self.print_section("TEST 2: Spot buy ETH <- USDC")
        
        if not self.spot_pair:
            self.print_error("No spot pair found; skipping spot buy")
            return False
        
        price = await self.get_market_price(self.spot_pair)
        if not price:
            return False
        
        # Calculate ETH amount we can buy.
        eth_amount = usdc_amount / price
        
        # Adjust amount to contract_size, if defined.
        if self.spot_contract_size:
            original_amount = eth_amount
            eth_amount = self.adjust_amount_to_contract_size(eth_amount, self.spot_contract_size)
            if abs(eth_amount - original_amount) > 0.0001:
                self.print_warning(
                    f"Adjusted amount: {original_amount:.6f} -> {eth_amount:.6f} ETH (multiple of contract_size)"
                )
                # Recalculate required USDC.
                usdc_amount = eth_amount * price
        
        self.print_info(f"Current price: ${price:,.2f}")
        self.print_info(f"USDC to use : ${usdc_amount:,.2f}")
        self.print_info(f"Expected ETH: {eth_amount:.6f} ETH")
        self.print_warning("⚠️  Using market orders; trades will fill immediately.")
        
        order_id = await self.place_market_order(self.spot_pair, eth_amount, "buy")
        if not order_id:
            return False
        
        self.print_success(f"Spot buy order created: {order_id}")
        await asyncio.sleep(2)  # wait for fills
        
        return True
    
    async def check_positions(self) -> Dict:
        """Fetch current ETH positions and return them as a dict keyed by instrument_name."""
        try:
            positions_tool = GetPositionsTool()
            result = await positions_tool.execute(currency="ETH")
            
            if isinstance(result, dict) and result.get("error"):
                return {}
            
            positions = result.get("output") if isinstance(result, dict) else result
            
            position_dict = {}
            for pos in positions:
                inst_name = pos.get("instrument_name")
                size = pos.get("size", 0)
                direction = pos.get("direction", "")
                if inst_name and size != 0:
                    position_dict[inst_name] = {
                        "size": size,
                        "direction": direction
                    }
            
            return position_dict
        except Exception as e:
            self.print_error(f"Exception while checking positions: {e}")
            return {}
    
    async def test_futures_buy(self, amount: float = 1.0) -> bool:
        """Test 3: open a small futures long position (then closed in the next step)."""
        self.print_section("TEST 3: Futures buy (low risk, will be closed later)")
        
        # Check current positions first
        positions = await self.check_positions()
        current_position = positions.get(self.futures_pair, {})
        current_size = current_position.get("size", 0)
        current_direction = current_position.get("direction", "")
        
        if current_size > 0:
            self.print_warning(f"Existing futures position: {current_size} contracts ({current_direction})")
            if current_direction == "buy":
                self.print_warning("Existing long position detected; consider closing it first.")
        
        price = await self.get_market_price(self.futures_pair)
        if not price:
            return False
        
        self.print_info(f"Current price: ${price:,.2f}")
        self.print_info(f"Buy amount   : {amount} contracts")
        self.print_warning("⚠️  Using market orders; trades will fill immediately.")
        self.print_warning("⚠️  This long will be closed immediately in the next step to reduce risk.")
        
        order_id = await self.place_market_order(self.futures_pair, amount, "buy")
        if not order_id:
            return False
        
        self.print_success(f"Futures buy order created: {order_id}")
        await asyncio.sleep(2)  # wait for fills
        
        # Verify the position exists
        positions_after = await self.check_positions()
        position_after = positions_after.get(self.futures_pair, {})
        size_after = position_after.get("size", 0)
        
        if size_after > 0:
            self.print_warning(f"Post-buy position size: {size_after} contracts")
            self.print_info("This will be closed in the next step (sell).")
        
        return True
    
    async def test_futures_sell(self, amount: float = 1.0) -> bool:
        """Test 4: close the futures position with a market sell (low risk)."""
        self.print_section("TEST 4: Futures sell (close position, low risk)")
        
        # Check current positions
        positions = await self.check_positions()
        current_position = positions.get(self.futures_pair, {})
        current_size = current_position.get("size", 0)
        current_direction = current_position.get("direction", "")
        
        if current_size == 0:
            self.print_warning("No existing futures position; selling would open a short.")
            self.print_warning("⚠️  To keep this test low-risk, we will not open new shorts automatically.")
            return False
        
        if current_direction != "buy":
            self.print_warning(f"Current position direction is {current_direction}, not a long.")
        
        # Only sell up to the current open size to avoid over-selling.
        sell_amount = min(amount, abs(current_size))
        
        price = await self.get_market_price(self.futures_pair)
        if not price:
            return False
        
        self.print_info(f"Current price : ${price:,.2f}")
        self.print_info(f"Current size  : {current_size} contracts ({current_direction})")
        self.print_info(f"Sell amount   : {sell_amount} contracts (close position)")
        self.print_warning("⚠️  Using market orders; trades will fill immediately.")
        self.print_success("✅ This is a close-position operation, risk is limited.")
        
        order_id = await self.place_market_order(self.futures_pair, sell_amount, "sell")
        if not order_id:
            return False
        
        self.print_success(f"Futures sell order created: {order_id}")
        await asyncio.sleep(2)  # wait for fills
        
        # Verify the position is closed
        positions_after = await self.check_positions()
        position_after = positions_after.get(self.futures_pair, {})
        size_after = position_after.get("size", 0)
        
        if size_after == 0:
            self.print_success("✅ Futures position fully closed.")
        else:
            self.print_warning(f"⚠️  Remaining futures position: {size_after} contracts")
        
        return True
    
    async def cleanup_orders(self):
        """Cancel all open spot/futures orders for this test."""
        self.print_section("Cleanup: cancel all spot and futures orders")
        
        if self.spot_pair:
            await self.cancel_all_orders(self.spot_pair)
        
        await self.cancel_all_orders(self.futures_pair)
        
        # Sanity-check no open orders remain.
        await self.verify_no_open_orders()
    
    async def calculate_consumption(self):
        """Compute net ETH consumption over the entire workflow."""
        self.print_section("Compute ETH consumption")
        
        self.final_eth_balance = await self.get_account_balance("ETH")
        
        if self.initial_eth_balance is not None and self.final_eth_balance is not None:
            self.eth_consumed = self.initial_eth_balance - self.final_eth_balance
            
            self.print_info(f"Initial balance: {self.initial_eth_balance:.6f} ETH")
            self.print_info(f"Final balance  : {self.final_eth_balance:.6f} ETH")
            self.print_info(f"Delta (spent) : {self.eth_consumed:.6f} ETH")
            
            if self.eth_consumed > 0:
                usd_value = self.eth_consumed * (await self.get_market_price(self.spot_pair) or 0)
                self.print_warning(f"Approximate cost: ~${usd_value:,.2f} USD")
            else:
                self.print_success("No net ETH consumed (balance may have increased).")
        else:
            self.print_warning("Unable to compute consumption (missing balance information).")
    
    async def run_complete_test(self):
        """Run the complete workflow: spot sell/buy + futures buy/sell + cleanup + summary."""
        self.print_header("Deribit complete trading workflow test")
        
        print(f"{Colors.YELLOW}Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}\n")
        
        print("This workflow test will perform:")
        print("  1. ⚠️ Spot sell ETH -> USDC (market, immediate fill)")
        print("  2. ⚠️ Spot buy  ETH <- USDC (market, immediate fill)")
        print("  3. ⚠️ Futures buy (market, immediate fill)")
        print("  4. ⚠️ Futures sell to close (market, immediate fill)")
        print("  5. ✅ Cleanup all open orders")
        print("  6. ✅ Compute final ETH consumption")
        print()
        
        self.print_warning("⚠️ WARNING: This script performs real trades with real funds!")
        print()
        
        # STEP 0: initial balance
        self.print_section("STEP 0: Get initial ETH balance")
        self.initial_eth_balance = await self.get_account_balance("ETH")
        if self.initial_eth_balance is None:
            self.print_error("Failed to fetch initial balance, aborting test.")
            return
        
        self.print_success(f"Initial ETH balance: {self.initial_eth_balance:.6f} ETH")
        
        # Basic safeguard for extremely small balances.
        if self.initial_eth_balance < 0.01:
            self.print_error("Balance is too low (< 0.01 ETH) to safely run this test.")
            return
        
        # STEP 1: spot discovery
        self.print_section("STEP 1: Discover spot trading pair")
        self.spot_pair = await self.find_spot_pair()
        if not self.spot_pair:
            self.print_error("No spot pair found; spot leg will be skipped.")
        else:
            self.print_success(f"Selected spot instrument: {self.spot_pair}")
        
        # Use 30% of initial ETH balance in the spot leg.
        test_eth_amount = self.initial_eth_balance * 0.3
        self.print_info(f"Using {test_eth_amount:.6f} ETH for spot test (~30% of balance).")
        
        # STEP 2: Spot sell + buy
        if self.spot_pair:
            success = await self.test_spot_sell(test_eth_amount)
            if not success:
                self.print_warning("Spot sell leg failed; continuing with the rest of the workflow.")
            
            # Wait for settlement and then check USDC balance
            await asyncio.sleep(2)
            usdc_balance = await self.get_account_balance("USDC")
            if usdc_balance:
                self.print_info(f"Current USDC balance: {usdc_balance:.2f} USDC")
                # Use 80% of USDC to buy back ETH, leaving some for fees.
                buy_usdc_amount = usdc_balance * 0.8
                
                success = await self.test_spot_buy(buy_usdc_amount)
                if not success:
                    self.print_warning("Spot buy leg failed; continuing with futures test.")
        
        # STEP 3: Futures buy (low-risk leg)
        await asyncio.sleep(1)
        self.print_warning("⚠️  Futures leg about to run; risk notes:")
        self.print_info("  - Buy 1 contract and then immediately sell to close.")
        self.print_info("  - Market orders imply some slippage and fees.")
        self.print_info("  - If balance is insufficient, the call should still validate the interface.")
        
        success = await self.test_futures_buy(amount=1.0)
        if not success:
            self.print_warning("Futures buy leg failed; skipping futures sell.")
        else:
            # STEP 4: Futures sell (close the position)
            await asyncio.sleep(1)
            self.print_info("Closing the futures position immediately to limit risk...")
            success = await self.test_futures_sell(amount=1.0)
            if not success:
                self.print_warning("Futures sell leg failed; you may need to close positions manually.")
                
                # Provide an explicit reminder about any remaining positions.
                positions = await self.check_positions()
                if positions:
                    self.print_error("⚠️  Open positions remain; please close them manually!")
                    for inst, pos in positions.items():
                        self.print_error(f"  {inst}: {pos['size']} contracts ({pos['direction']})")
        
        # STEP 5: Cleanup all orders
        await self.cleanup_orders()
        
        # STEP 6: Compute net ETH consumption
        await self.calculate_consumption()
        
        # Final report
        self.print_header("Workflow test summary")
        
        self.print_info(f"Initial ETH: {self.initial_eth_balance:.6f} ETH")
        if self.final_eth_balance is not None:
            self.print_info(f"Final ETH  : {self.final_eth_balance:.6f} ETH")
            self.print_info(f"Net delta  : {self.eth_consumed:.6f} ETH")
        
        self.print_info(f"Total orders created: {len(self.created_orders)}")
        
        # Verify final account state
        final_balance = await self.get_account_balance("ETH")
        if final_balance is not None:
            if final_balance > 0:
                self.print_success(f"✅ Account still holds ETH balance: {final_balance:.6f} ETH")
            else:
                self.print_warning("⚠️  Account ETH balance is zero.")
        
        # Ensure no positions remain.
        final_positions = await self.check_positions()
        if final_positions:
            self.print_error("⚠️  Positions still open; please close them manually.")
            for inst, pos in final_positions.items():
                if pos["size"] != 0:
                    self.print_error(f"  {inst}: {pos['size']} contracts ({pos['direction']})")
        else:
            self.print_success("✅ Confirmed there are no open positions.")
        
        await self.verify_no_open_orders()
        
        # Compact trade-record summary
        if self.trade_records:
            self.print_section("Recorded trades overview")
            self.print_info(f"Total trade records: {len(self.trade_records)}")
            
            successful_trades = [r for r in self.trade_records if r.get("status") != "failed"]
            failed_trades = [r for r in self.trade_records if r.get("status") == "failed"]
            
            if successful_trades:
                self.print_success(f"\n✅ Successful trades: {len(successful_trades)}")
                for i, record in enumerate(successful_trades, 1):
                    self.print_info(f"\nTrade {i} (SUCCESS):")
                    self.print_info(f"  order_id: {record.get('order_id')}")
                    self.print_info(f"  symbol  : {record.get('instrument_name')}")
                    self.print_info(f"  side    : {record.get('side').upper()}")
                    self.print_info(f"  amount  : {record.get('amount')}")
                    if record.get("order_data"):
                        order = record["order_data"]
                        self.print_success(f"  state   : {order.get('order_state', 'N/A')}")
                        if order.get("average_price"):
                            self.print_success(f"  avg_px  : {order.get('average_price')}")
                    if record.get("trade_data"):
                        trade = record["trade_data"]
                        self.print_success(f"  trade_px: {trade.get('price')}")
                        self.print_success(f"  trade_sz: {trade.get('amount')}")
            
            if failed_trades:
                self.print_warning(f"\n⚠️  Failed trades: {len(failed_trades)}")
                for i, record in enumerate(failed_trades, 1):
                    self.print_info(f"\nTrade {i} (FAILED):")
                    self.print_info(f"  symbol : {record.get('instrument_name')}")
                    self.print_info(f"  side   : {record.get('side').upper()}")
                    self.print_info(f"  amount : {record.get('amount')}")
                    self.print_error(f"  error  : {record.get('error', 'Unknown error')}")
            
            self.print_success(f"\n✅ All trade records persisted to: {self.log_file}")
        
        self.print_success("🎉 Complete workflow test finished.")


async def main():
    test = TradingWorkflowTest()
    await test.run_complete_test()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Workflow test interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"\n\n{Colors.RED}Workflow test failed with exception: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()

