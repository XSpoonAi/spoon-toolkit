"""Comprehensive options test: buy + sell + trade logging + funding tracking + final checks."""

import asyncio
import sys
from pathlib import Path
import importlib.util
import json
from datetime import datetime
from typing import Dict, List, Optional
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
account_module = load_module('account', deribit_path / 'account.py')
trading_module = load_module('trading', deribit_path / 'trading.py')

GetInstrumentsTool = market_module.GetInstrumentsTool
GetTickerTool = market_module.GetTickerTool
GetAccountSummaryTool = account_module.GetAccountSummaryTool
GetPositionsTool = account_module.GetPositionsTool
GetOrderHistoryTool = account_module.GetOrderHistoryTool
GetTradeHistoryTool = account_module.GetTradeHistoryTool
GetOpenOrdersTool = trading_module.GetOpenOrdersTool
PlaceBuyOrderTool = trading_module.PlaceBuyOrderTool
PlaceSellOrderTool = trading_module.PlaceSellOrderTool
CancelOrderTool = trading_module.CancelOrderTool
CancelAllOrdersTool = trading_module.CancelAllOrdersTool


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class OptionsTradingTest:
    """Comprehensive options trading test."""
    
    def __init__(self):
        self.initial_eth_balance = None
        self.final_eth_balance = None
        self.eth_consumed = 0.0
        
        # Option instrument info
        self.options_pair = None
        self.options_contract_size = None
        self.options_tick_size = None
        self.options_currency = None
        
        # Trade records
        self.trade_records: List[Dict] = []
        self.all_order_ids: List[str] = []
        
        # Funding tracking
        self.funding_tracking: List[Dict] = []
        
        # Log file
        log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = log_dir / f"options_trading_log_{timestamp}.json"
        
    def print_header(self, text: str):
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{text:^70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    def print_success(self, text: str):
        print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")
    
    def print_error(self, text: str):
        print(f"{Colors.RED}❌ {text}{Colors.RESET}")
    
    def print_info(self, text: str):
        print(f"{Colors.CYAN}ℹ️  {text}{Colors.RESET}")
    
    def print_warning(self, text: str):
        print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")
    
    async def get_eth_balance(self) -> Optional[float]:
        """Get ETH balance."""
        try:
            tool = GetAccountSummaryTool()
            result = await tool.execute(currency="ETH")
            
            if isinstance(result, dict) and result.get("error"):
                self.print_error(f"Failed to get account balance: {result.get('error')}")
                return None
            
            account = result.get("output") if isinstance(result, dict) else result
            balance = account.get("balance", 0)
            return float(balance)
        except Exception as e:
            self.print_error(f"Exception while getting account balance: {e}")
            return None
    
    async def find_options_pair(self) -> bool:
        """Find an options instrument to trade."""
        self.print_header("STEP 1: Find options instrument")
        try:
            tool = GetInstrumentsTool()
            
            # Prefer ETH options
            result = await tool.execute(currency="ETH", kind="option", expired=False)
            
            if isinstance(result, dict) and result.get("error"):
                self.print_error(f"Failed to query options instruments: {result.get('error')}")
                return False
            
            instruments = result.get("output") if isinstance(result, dict) else result
            
            if not instruments:
                self.print_error("No ETH options instruments found")
                return False
            
            # Prefer a call option if available
            call_option = None
            put_option = None
            
            for inst in instruments:
                inst_name = inst.get("instrument_name", "")
                if inst_name.endswith("-C") and not call_option:
                    call_option = inst
                elif inst_name.endswith("-P") and not put_option:
                    put_option = inst
            
            selected_option = call_option if call_option else put_option
            
            if selected_option:
                self.options_pair = selected_option.get("instrument_name")
                self.options_contract_size = selected_option.get("contract_size")
                self.options_tick_size = selected_option.get("tick_size")
                self.options_currency = selected_option.get("currency", "ETH")
                
                self.print_success(f"Selected options instrument: {self.options_pair}")
                self.print_info(f"  type       : {'Call' if self.options_pair.endswith('-C') else 'Put'}")
                self.print_info(f"  currency   : {self.options_currency}")
                self.print_info(f"  contract   : {self.options_contract_size}")
                self.print_info(f"  tick_size  : {self.options_tick_size}")
                self.print_info(f"  min amount : {selected_option.get('min_trade_amount', 'N/A')}")
                
                return True
            else:
                self.print_error("No suitable options instrument found")
                return False
        except Exception as e:
            self.print_error(f"Exception while finding options instrument: {e}")
            return False
    
    async def get_market_price(self, instrument_name: str) -> Optional[float]:
        """Get last or mark price for an instrument."""
        try:
            tool = GetTickerTool()
            result = await tool.execute(instrument_name=instrument_name)
            
            if isinstance(result, dict) and result.get("error"):
                return None
            
            ticker = result.get("output") if isinstance(result, dict) else result
            price = ticker.get("last_price") or ticker.get("mark_price")
            return float(price) if price else None
        except Exception as e:
            self.print_error(f"Exception while getting price: {e}")
            return None
    
    def adjust_price_to_tick_size(self, price: float, tick_size: float) -> float:
        """Adjust a price to be a multiple of ``tick_size``."""
        if tick_size <= 0:
            return price
        
        price_decimal = Decimal(str(price))
        tick_decimal = Decimal(str(tick_size))
        
        # Round down to a multiple of tick_size
        adjusted = (price_decimal / tick_decimal).quantize(Decimal('1'), rounding=ROUND_DOWN) * tick_decimal
        
        # Compute precision from tick_size
        tick_size_str = str(tick_size)
        if '.' in tick_size_str:
            decimals = len(tick_size_str.split('.')[1])
        else:
            decimals = 0
        
        return float(round(adjusted, decimals))
    
    async def place_market_order(self, instrument_name: str, amount: float, side: str) -> Optional[str]:
        """Place a market order."""
        try:
            tool = PlaceBuyOrderTool() if side == "buy" else PlaceSellOrderTool()
            result = await tool.execute(
                instrument_name=instrument_name,
                amount=amount,
                order_type="market"
            )
            
            if isinstance(result, dict) and result.get("error"):
                error_msg = result.get("error", "")
                self.print_error(f"{side.upper()} order failed: {error_msg}")
                self.log_failed_trade(instrument_name, side, amount, error_msg)
                return None
            
            order = result.get("output", {}).get("order", {}) if isinstance(result, dict) else result.get("order", {})
            order_id = order.get("order_id")
            
            if order_id:
                self.all_order_ids.append(order_id)
                await asyncio.sleep(2)  # wait for fills
                await self.query_and_log_trade(instrument_name, order_id, side, amount)
                return order_id
            
            return None
        except Exception as e:
            self.print_error(f"Exception while placing market order: {e}")
            self.log_failed_trade(instrument_name, side, amount, str(e))
            return None
    
    async def place_limit_order(self, instrument_name: str, amount: float, price: float, side: str) -> Optional[str]:
        """Place a limit order."""
        try:
            # Do not manually adjust price here; the tools will validate and adjust
            tool = PlaceBuyOrderTool() if side == "buy" else PlaceSellOrderTool()
            result = await tool.execute(
                instrument_name=instrument_name,
                amount=amount,
                price=price,
                order_type="limit"
            )
            
            if isinstance(result, dict) and result.get("error"):
                error_msg = result.get("error", "")
                self.print_error(f"{side.upper()} order failed: {error_msg}")
                self.log_failed_trade(instrument_name, side, amount, error_msg)
                return None
            
            order = result.get("output", {}).get("order", {}) if isinstance(result, dict) else result.get("order", {})
            order_id = order.get("order_id")
            
            if order_id:
                self.all_order_ids.append(order_id)
                self.print_success(f"{side.upper()} limit order created: {order_id}")
                self.print_info(f"  price : ${price:,.4f}")
                self.print_info(f"  amount: {amount}")
                return order_id
            
            return None
        except Exception as e:
            self.print_error(f"Exception while placing limit order: {e}")
            self.log_failed_trade(instrument_name, side, amount, str(e))
            return None
    
    async def query_and_log_trade(self, instrument_name: str, order_id: str, side: str, amount: float):
        """Query order/trade history for an order and log the result."""
        try:
            # Query order history
            order_tool = GetOrderHistoryTool()
            order_result = await order_tool.execute(
                instrument_name=instrument_name,
                count=20
            )
            
            order_data = None
            if isinstance(order_result, dict) and not order_result.get("error"):
                orders = order_result.get("output", [])
                if isinstance(orders, list):
                    for order in orders:
                        if order.get("order_id") == order_id:
                            order_data = order
                            break
            
            # Query trade history
            trade_tool = GetTradeHistoryTool()
            trade_result = await trade_tool.execute(
                instrument_name=instrument_name,
                count=20
            )
            
            trade_data = None
            if isinstance(trade_result, dict) and not trade_result.get("error"):
                trades = trade_result.get("output", [])
                if isinstance(trades, list):
                    for trade in trades:
                        if isinstance(trade, dict) and trade.get("order_id") == order_id:
                            trade_data = trade
                            break
            
            # Build trade record
            trade_record = {
                "timestamp": datetime.now().isoformat(),
                "order_id": order_id,
                "instrument_name": instrument_name,
                "side": side.upper(),
                "amount": amount,
                "order_data": order_data,
                "trade_data": trade_data,
                "status": "success" if order_data else "pending"
            }
            
            self.trade_records.append(trade_record)
            
            # Print trade record
            self.print_header(f"Trade record - {side.upper()} {instrument_name}")
            if order_data:
                self.print_info(f"Order ID   : {order_id}")
                self.print_info(f"Order state: {order_data.get('order_state', 'N/A')}")
                self.print_info(f"Order type : {order_data.get('order_type', 'N/A')}")
                self.print_info(f"Amount     : {order_data.get('amount', 'N/A')}")
                avg_price = order_data.get('average_price') or order_data.get('price')
                if avg_price:
                    self.print_info(f"Average price: ${avg_price:,.4f}")
            else:
                self.print_warning("Order data not found")
            
            if trade_data:
                if trade_data.get('price'):
                    self.print_info(f"Trade price : ${trade_data.get('price', 'N/A'):,.4f}")
                else:
                    self.print_info("Trade price : N/A")
                self.print_info(f"Trade amount: {trade_data.get('amount', 'NA')}")
            else:
                self.print_warning("No trade data found (order may not be filled yet)")
            
            # Persist to log file
            self.write_trade_log(trade_record)
            
        except Exception as e:
            self.print_error(f"Exception while querying trade record: {e}")
    
    def log_failed_trade(self, instrument_name: str, side: str, amount: float, error_msg: str):
        """Record a failed trade attempt."""
        failed_record = {
            "timestamp": datetime.now().isoformat(),
            "instrument_name": instrument_name,
            "side": side.upper(),
            "amount": amount,
            "status": "failed",
            "error": error_msg
        }
        self.trade_records.append(failed_record)
        self.write_trade_log(failed_record)
    
    def write_trade_log(self, record: Dict):
        """Append a trade record to the JSON log file."""
        try:
            if self.log_file.exists():
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                data = []
            
            data.append(record)
            
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.print_error(f"Exception while writing trade log: {e}")
    
    async def track_funding(self, action: str, instrument_name: str, amount: float, price: Optional[float] = None):
        """Track funding usage and current ETH balance at each step."""
        balance = await self.get_eth_balance()
        record = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "instrument_name": instrument_name,
            "amount": amount,
            "price": price,
            "eth_balance": balance
        }
        self.funding_tracking.append(record)
        if balance is not None:
            self.print_info(f"Funding: {action} | balance: {balance:.6f} ETH")
        else:
            self.print_info(f"Funding: {action} | balance: N/A")
    
    async def test_options_buy(self, use_limit_order: bool = False) -> bool:
        """Test options buy leg."""
        self.print_header("TEST 1: Options buy")
        
        if not self.options_pair:
            self.print_error("No options instrument selected")
            return False
        
        price = await self.get_market_price(self.options_pair)
        if not price:
            self.print_error("Unable to fetch option price")
            return False
        
        # Use minimal trade unit
        amount = self.options_contract_size if self.options_contract_size and self.options_contract_size > 0 else 1.0
        
        # Check if balance is sufficient
        balance = await self.get_eth_balance()
        estimated_cost = price * amount  # estimated option premium
        
        self.print_info(f"Instrument     : {self.options_pair}")
        self.print_info(f"Buy amount     : {amount} contracts")
        self.print_info(f"Current price  : ${price:,.4f}")
        self.print_info(f"Estimated cost : ${estimated_cost:,.2f}")
        self.print_info(f"Current ETH bal: {balance:.6f} ETH" if balance else "Current ETH bal: N/A")
        
        # If funds are likely insufficient, fall back to a deep limit order (won't fill)
        if balance and estimated_cost > balance * 3000:
            self.print_warning("⚠️  Balance may be insufficient; using a deep limit order test instead.")
            use_limit_order = True
        
        if use_limit_order:
            # Use a limit order with price at 50% of current price.
            # Note: PlaceBuyOrderTool/PlaceSellOrderTool will validate and adjust to tick size.
            limit_price = price * 0.5

            # Pre-adjust price to conform to tick_size to avoid validation failures.
            if self.options_tick_size:
                limit_price = self.adjust_price_to_tick_size(limit_price, self.options_tick_size)

            self.print_info(
                f"Limit price: ${limit_price:,.4f} (should not fill; already adjusted to tick_size)"
            )
            await self.track_funding(
                "options_buy_before_limit_order", self.options_pair, amount, limit_price
            )
            buy_order_id = await self.place_limit_order(self.options_pair, amount, limit_price, "buy")
            await self.track_funding(
                "options_buy_after_limit_order", self.options_pair, amount, limit_price
            )
        else:
            self.print_warning("⚠️  Using market order; this will fill immediately.")
            await self.track_funding("options_buy_before_market_order", self.options_pair, amount, price)
            buy_order_id = await self.place_market_order(self.options_pair, amount, "buy")
            await self.track_funding("options_buy_after_market_order", self.options_pair, amount, price)
        
        if buy_order_id:
            self.print_success("Options buy order created successfully")
            return True
        else:
            self.print_error("Options buy failed")
            return False
    
    async def test_options_sell(self) -> bool:
        """Test options sell leg."""
        self.print_header("TEST 2: Options sell")
        
        if not self.options_pair:
            self.print_error("No options instrument found")
            return False
        
        # Check current positions
        positions_tool = GetPositionsTool()
        positions_result = await positions_tool.execute(currency=self.options_currency, kind="option")
        
        current_position = 0
        if isinstance(positions_result, dict) and not positions_result.get("error"):
            positions = positions_result.get("output", [])
            for pos in positions:
                if pos.get("instrument_name") == self.options_pair:
                    current_position = pos.get("size", 0)
                    break
        
        if current_position <= 0:
            self.print_warning(
                f"No open position for {self.options_pair} (current position: {current_position})"
            )
            self.print_warning("Cannot sell option (you need an open long position first).")
            return False
        
        price = await self.get_market_price(self.options_pair)
        if not price:
            self.print_error("Unable to fetch option price")
            return False
        
        # Sell the current position size
        amount = abs(current_position)
        if self.options_contract_size:
            # Ensure the amount is a multiple of contract_size.
            amount = round(amount / self.options_contract_size) * self.options_contract_size
        
        self.print_info(f"Instrument : {self.options_pair}")
        self.print_info(f"Sell amount: {amount} contracts (closing position)")
        self.print_info(f"Price      : ${price:,.4f}")
        self.print_warning("⚠️  Using market order; this will fill immediately.")
        
        await self.track_funding("options_sell_before_market_order", self.options_pair, amount, price)
        sell_order_id = await self.place_market_order(self.options_pair, amount, "sell")
        await self.track_funding("options_sell_after_market_order", self.options_pair, amount, price)
        
        if sell_order_id:
            self.print_success("Options sell completed successfully")
            return True
        else:
            self.print_error("Options sell failed")
            return False
    
    async def cleanup_all_orders(self) -> bool:
        """Cancel all open option orders."""
        self.print_header("STEP 3: Cancel all open orders")
        
        try:
            # Cancel all option orders
            cancel_tool = CancelAllOrdersTool()
            result = await cancel_tool.execute(currency=self.options_currency, kind="option")
            
            if isinstance(result, dict) and result.get("error"):
                self.print_error(f"Failed to cancel all orders: {result.get('error')}")
                return False
            
            self.print_success("All option orders have been cancelled")
            return True
        except Exception as e:
            self.print_error(f"Exception while cancelling orders: {e}")
            return False
    
    async def close_all_positions(self) -> bool:
        """Close all remaining option positions."""
        self.print_header("STEP 4: Close all positions")
        
        try:
            positions_tool = GetPositionsTool()
            result = await positions_tool.execute(currency=self.options_currency, kind="option")
            
            if isinstance(result, dict) and result.get("error"):
                self.print_error(f"Failed to query positions: {result.get('error')}")
                return False
            
            positions = result.get("output", []) if isinstance(result, dict) else result
            
            if not positions:
                self.print_success("No positions to close")
                return True
            
            closed = False
            for pos in positions:
                inst_name = pos.get("instrument_name")
                size = pos.get("size", 0)
                direction = pos.get("direction", "")
                
                if abs(size) > 0.0001:  # non-zero position
                    self.print_info(
                        f"Found position: {inst_name} | size: {size} | direction: {direction}"
                    )
                    
                    # Close position
                    side = "sell" if size > 0 else "buy"
                    close_amount = abs(size)
                    
                    self.print_info(f"Closing position: {side} {close_amount} {inst_name}")
                    order_id = await self.place_market_order(inst_name, close_amount, side)
                    
                    if order_id:
                        closed = True
                        await asyncio.sleep(2)
            
            if closed:
                self.print_success("All option positions have been closed")
            else:
                self.print_success("No positions required closing")
            
            return True
        except Exception as e:
            self.print_error(f"Exception while closing positions: {e}")
            return False
    
    async def verify_final_state(self) -> bool:
        """Verify final account state after the test."""
        self.print_header("STEP 5: Verify final state")
        
        # Check balance
        balance = await self.get_eth_balance()
        if balance:
            self.print_info(f"Final ETH balance: {balance:.6f} ETH")
            self.final_eth_balance = balance
            
            if self.initial_eth_balance:
                consumed = self.initial_eth_balance - balance
                self.eth_consumed = consumed
                self.print_info(f"ETH consumed: {consumed:.6f} ETH")
        
        # Check open orders
        open_orders = []
        try:
            orders_tool = GetOpenOrdersTool()
            orders_result = await orders_tool.execute(currency=self.options_currency, kind="option")
            
            if isinstance(orders_result, dict) and not orders_result.get("error"):
                open_orders = orders_result.get("output", [])
        except Exception as e:
            self.print_warning(f"Exception while querying open orders: {e}")
        
        if open_orders:
            self.print_error(f"There are still {len(open_orders)} open orders")
            for order in open_orders:
                self.print_error(f"  - {order.get('order_id')} | {order.get('instrument_name')}")
            return False
        else:
            self.print_success("No open orders")
        
        # Check positions
        positions_tool = GetPositionsTool()
        positions_result = await positions_tool.execute(currency=self.options_currency, kind="option")
        
        positions = []
        if isinstance(positions_result, dict) and not positions_result.get("error"):
            positions = positions_result.get("output", [])
        
        active_positions = []
        for pos in positions:
            size = abs(pos.get("size", 0))
            if size > 0.0001:
                active_positions.append(pos)

        if active_positions:
            self.print_error(f"There are still {len(active_positions)} open positions")
            for pos in active_positions:
                self.print_error(
                    f"  - {pos.get('instrument_name')} | size: {pos.get('size')}"
                )
            return False
        else:
            self.print_success("No open positions")
        
        self.print_success(
            "✅ Final state verified: account has only ETH, with no open orders or positions"
        )
        return True
    
    async def print_summary(self):
        """Print a human-readable test summary."""
        self.print_header("Test summary")
        
        self.print_info(
            f"Initial ETH balance: {self.initial_eth_balance:.6f} ETH"
            if self.initial_eth_balance
            else "Initial ETH balance: N/A"
        )
        self.print_info(
            f"Final ETH balance  : {self.final_eth_balance:.6f} ETH"
            if self.final_eth_balance
            else "Final ETH balance  : N/A"
        )
        self.print_info(
            f"ETH consumed       : {self.eth_consumed:.6f} ETH"
            if self.eth_consumed
            else "ETH consumed       : N/A"
        )
        
        self.print_info(f"\nTotal trade records: {len(self.trade_records)}")
        successful = [r for r in self.trade_records if r.get("status") == "success"]
        failed = [r for r in self.trade_records if r.get("status") == "failed"]
        
        self.print_success(f"Successful trades: {len(successful)}")
        if failed:
            self.print_error(f"Failed trades    : {len(failed)}")
        
        if successful:
            self.print_info("\nSuccessful trade details:")
            for i, record in enumerate(successful, 1):
                order_id = record.get("order_id", "N/A")
                side = record.get("side", "N/A")
                amount = record.get("amount", "N/A")
                order_data = record.get("order_data", {})
                avg_price = order_data.get("average_price") or order_data.get("price") if order_data else None
                
                self.print_info(f"  {i}. {side} | amount: {amount} | order: {order_id}")
                if avg_price:
                    self.print_info(f"     average price: ${avg_price:,.4f}")
        
        if failed:
            self.print_info("\nFailed trade details:")
            for i, record in enumerate(failed, 1):
                side = record.get("side", "N/A")
                amount = record.get("amount", "N/A")
                error = record.get("error", "N/A")
                self.print_error(f"  {i}. {side} | amount: {amount} | error: {error[:100]}")
        
        self.print_info(f"\nLog file: {self.log_file}")
    
    async def run_complete_test(self):
        """Run the complete options trading test."""
        self.print_header("Options complete trading test")
        
        self.print_warning("⚠️  This test performs real trades with real funds.")
        self.print_warning(
            "⚠️  After all trades, the account should have only ETH, with no open orders or positions."
        )
        
        # Step 0: Get initial balance
        self.print_header("STEP 0: Get initial balance")
        self.initial_eth_balance = await self.get_eth_balance()
        if self.initial_eth_balance:
            self.print_success(f"Initial ETH balance: {self.initial_eth_balance:.6f} ETH")
        else:
            self.print_error("Unable to fetch initial balance")
            return
        
        # Step 1: Find an options instrument
        if not await self.find_options_pair():
            return
        
        await asyncio.sleep(1)
        
        # Step 2: Execute trades
        # Try market order first; if funds are insufficient, fall back to limit order.
        buy_success = await self.test_options_buy(use_limit_order=False)
        
        if not buy_success:
            # Market order failed; try a deep limit order instead.
            self.print_warning("Market order failed; trying limit order test instead.")
            await asyncio.sleep(2)
            buy_success = await self.test_options_buy(use_limit_order=True)
        
        await asyncio.sleep(2)
        
        if buy_success:
            # If buy leg succeeded, attempt sell leg.
            await asyncio.sleep(3)
            sell_success = await self.test_options_sell()
            await asyncio.sleep(2)
        else:
            self.print_warning("Buy leg failed; skipping sell test.")
            sell_success = False
        
        # Step 3: Cleanup
        await self.cleanup_all_orders()
        await asyncio.sleep(2)
        
        await self.close_all_positions()
        await asyncio.sleep(2)
        
        # Step 4: Verification
        await self.verify_final_state()
        
        # Step 5: Summary
        await self.print_summary()


async def main():
    test = OptionsTradingTest()
    await test.run_complete_test()


if __name__ == "__main__":
    asyncio.run(main())

