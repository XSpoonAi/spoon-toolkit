"""Comprehensive test: spot, futures, options – buy/sell + trade logs + funding tracking + final cleanup."""

import asyncio
import sys
from pathlib import Path
import importlib.util
import json
from datetime import datetime
from typing import Dict, List, Optional
from decimal import Decimal

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


class ComprehensiveTradingTest:
    """Comprehensive trading test covering spot, futures, and options."""
    
    def __init__(self):
        self.initial_eth_balance = None
        self.final_eth_balance = None
        self.eth_consumed = 0.0
        
        # Instruments used in this comprehensive test
        self.spot_pair = None
        self.spot_contract_size = None
        self.futures_pair = "ETH-PERPETUAL"
        self.options_pair = None
        self.options_contract_size = None
        
        # Trade records and created orders
        self.trade_records: List[Dict] = []
        self.all_order_ids: List[str] = []
        
        # Funding/balance tracking at each step
        self.funding_tracking: List[Dict] = []
        
        # Create a timestamped JSON log file
        log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = log_dir / f"comprehensive_trading_log_{timestamp}.json"
        
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
    
    async def find_spot_pair(self) -> bool:
        """Find a spot trading pair."""
        self.print_header("STEP 1: Find spot trading pair")
        try:
            tool = GetInstrumentsTool()
            result = await tool.execute(currency="ETH", kind="spot", expired=False)
            
            if isinstance(result, dict) and result.get("error"):
                self.print_error(f"Failed to query spot instruments: {result.get('error')}")
                return False
            
            instruments = result.get("output") if isinstance(result, dict) else result
            
            if not instruments:
                self.print_error("No ETH spot instruments found")
                return False
            
            for inst in instruments:
                inst_name = inst.get("instrument_name", "")
                if "USDC" in inst_name or "USDT" in inst_name:
                    self.spot_pair = inst_name
                    self.spot_contract_size = inst.get("contract_size")
                    self.print_success(f"Selected spot instrument: {self.spot_pair}")
                    self.print_info(f"Contract size: {self.spot_contract_size}")
                    return True
            
            # If no preferred pair is found, fall back to the first instrument.
            self.spot_pair = instruments[0].get("instrument_name")
            self.spot_contract_size = instruments[0].get("contract_size")
            self.print_success(f"Selected spot instrument: {self.spot_pair}")
            return True
        except Exception as e:
            self.print_error(f"Exception while finding spot instrument: {e}")
            return False
    
    async def find_options_pair(self) -> bool:
        """Find an options trading instrument."""
        self.print_header("STEP 2: Find options instrument")
        try:
            tool = GetInstrumentsTool()
            result = await tool.execute(currency="ETH", kind="option", expired=False)
            
            if isinstance(result, dict) and result.get("error"):
                self.print_error(f"Failed to query options instruments: {result.get('error')}")
                return False
            
            instruments = result.get("output") if isinstance(result, dict) else result
            
            if not instruments:
                self.print_warning("No ETH options instruments found")
                return False
            
            # Prefer a call option
            for inst in instruments:
                inst_name = inst.get("instrument_name", "")
                if inst_name.endswith("-C"):
                    self.options_pair = inst_name
                    self.options_contract_size = inst.get("contract_size")
                    self.print_success(f"Selected options instrument: {self.options_pair}")
                    self.print_info(f"Contract size: {self.options_contract_size}")
                    return True
            
            # If no call option was found, fall back to a put.
            for inst in instruments:
                inst_name = inst.get("instrument_name", "")
                if inst_name.endswith("-P"):
                    self.options_pair = inst_name
                    self.options_contract_size = inst.get("contract_size")
                    self.print_success(f"Selected options instrument: {self.options_pair}")
                    self.print_info(f"Contract size: {self.options_contract_size}")
                    return True
            
            return False
        except Exception as e:
            self.print_error(f"Exception while finding options instrument: {e}")
            return False
    
    def adjust_amount_to_contract_size(self, amount: float, contract_size: float) -> float:
        """Adjust amount to be a multiple of contract_size."""
        if contract_size <= 0:
            return amount
        
        amount_decimal = Decimal(str(amount))
        contract_decimal = Decimal(str(contract_size))
        multiple = round(amount_decimal / contract_decimal)
        
        if multiple < 1:
            multiple = 1
        
        adjusted = multiple * contract_decimal
        
        contract_size_str = str(contract_size)
        if '.' in contract_size_str:
            decimals = len(contract_size_str.split('.')[1])
        else:
            decimals = 0
        
        return float(round(adjusted, decimals))
    
    async def get_market_price(self, instrument_name: str) -> Optional[float]:
        """Get last/mark price for an instrument."""
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
            self.print_error(f"Exception while placing order: {e}")
            self.log_failed_trade(instrument_name, side, amount, str(e))
            return None
    
    async def query_and_log_trade(self, instrument_name: str, order_id: str, side: str, amount: float):
        """Query and log trade/order data for a given order."""
        try:
            # Query order history
            order_tool = GetOrderHistoryTool()
            order_result = await order_tool.execute(
                instrument_name=instrument_name,
                count=10
            )
            
            order_data = None
            if isinstance(order_result, dict) and not order_result.get("error"):
                orders = order_result.get("output", [])
                for order in orders:
                    if order.get("order_id") == order_id:
                        order_data = order
                        break
            
            # Query trade history
            trade_tool = GetTradeHistoryTool()
            trade_result = await trade_tool.execute(
                instrument_name=instrument_name,
                count=10
            )
            
            trade_data = None
            if isinstance(trade_result, dict) and not trade_result.get("error"):
                trades = trade_result.get("output", [])
                if isinstance(trades, list):
                    for trade in trades:
                        if trade.get("order_id") == order_id:
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
                self.print_info(f"Price      : {order_data.get('average_price', order_data.get('price', 'N/A'))}")
            else:
                self.print_warning("Order data not found")
            
            if trade_data:
                self.print_info(f"Trade price : {trade_data.get('price', 'N/A')}")
                self.print_info(f"Trade amount: {trade_data.get('amount', 'N/A')}")
            
            # Persist record
            self.write_trade_log(trade_record)
            
        except Exception as e:
            self.print_error(f"Exception while querying trade record: {e}")
    
    def log_failed_trade(self, instrument_name: str, side: str, amount: float, error_msg: str):
        """Record a failed trade attempt and write it to the log file."""
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
        """Write a trade record into the JSON log file."""
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
        """Track balance usage and log ETH balance at each step."""
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
        self.print_info(f"Funding: {action} | balance: {balance} ETH")
    
    async def test_spot_trading(self) -> bool:
        """Test spot trading: sell then buy back."""
        self.print_header("TEST 1: Spot trading (sell + buy)")
        
        if not self.spot_pair:
            self.print_error("No spot pair found, skipping spot test")
            return False
        
        price = await self.get_market_price(self.spot_pair)
        if not price:
            self.print_error("Unable to fetch spot price")
            return False
        
        # Use 30% of balance for the spot test
        balance = await self.get_eth_balance()
        if not balance:
            return False
        
        eth_amount = balance * 0.3
        
        # Adjust amount to contract_size, if any
        if self.spot_contract_size:
            eth_amount = self.adjust_amount_to_contract_size(eth_amount, self.spot_contract_size)
        
        self.print_info(f"Current price: ${price:,.2f}")
        self.print_info(f"Sell amount : {eth_amount} ETH")
        self.print_warning("⚠️  Using market orders; trades will fill immediately.")
        
        # Sell ETH -> USDC
        await self.track_funding("spot_sell_before", self.spot_pair, eth_amount, price)
        sell_order_id = await self.place_market_order(self.spot_pair, eth_amount, "sell")
        await self.track_funding("spot_sell_after", self.spot_pair, eth_amount, price)
        
        if not sell_order_id:
            self.print_error("Spot sell failed")
            return False
        
        await asyncio.sleep(2)
        
        # Buy ETH <- USDC using the USDC obtained from the previous sell.
        new_price = await self.get_market_price(self.spot_pair)
        if new_price:
            price = new_price
        
        # Wait for settlement
        await asyncio.sleep(3)
        
        # Calculate how much ETH we can buy based on USDC balance
        usdc_balance = await self.get_usdc_balance()
        if usdc_balance and usdc_balance > 1.0:  # require at least 1 USDC
            # Use 90% of USDC balance, reserving some for fees.
            usable_usdc = usdc_balance * 0.9
            buy_eth_amount = usable_usdc / price
            if self.spot_contract_size:
                buy_eth_amount = self.adjust_amount_to_contract_size(buy_eth_amount, self.spot_contract_size)
            
            # Ensure the ETH amount does not exceed the affordable maximum given usable_usdc.
            max_eth = usable_usdc / price
            if buy_eth_amount > max_eth:
                buy_eth_amount = max_eth
                if self.spot_contract_size:
                    buy_eth_amount = self.adjust_amount_to_contract_size(buy_eth_amount, self.spot_contract_size)
        else:
            self.print_warning(
                f"Insufficient USDC balance: {usdc_balance if usdc_balance else 0}; skipping spot buy"
            )
            return False
        
        await self.track_funding("spot_buy_before", self.spot_pair, buy_eth_amount, price)
        buy_order_id = await self.place_market_order(self.spot_pair, buy_eth_amount, "buy")
        await self.track_funding("spot_buy_after", self.spot_pair, buy_eth_amount, price)
        
        if buy_order_id:
            self.print_success("Spot round-trip completed")
            return True
        else:
            self.print_error("Spot buy failed")
            return False
    
    async def get_usdc_balance(self) -> Optional[float]:
        """Get USDC balance."""
        try:
            tool = GetAccountSummaryTool()
            result = await tool.execute(currency="USDC")
            
            if isinstance(result, dict) and result.get("error"):
                return None
            
            account = result.get("output") if isinstance(result, dict) else result
            balance = account.get("balance", 0)
            return float(balance)
        except Exception:
            return None
    
    async def test_futures_trading(self) -> bool:
        """Test futures trading: open and then close a small position."""
        self.print_header("TEST 2: Futures trading (buy + sell)")
        
        # Check current positions
        positions_tool = GetPositionsTool()
        positions_result = await positions_tool.execute(currency="ETH", kind="future")
        
        current_position = 0
        if isinstance(positions_result, dict) and not positions_result.get("error"):
            positions = positions_result.get("output", [])
            for pos in positions:
                if pos.get("instrument_name") == self.futures_pair:
                    current_position = pos.get("size", 0)
                    break
        
        # Buy 1 contract
        amount = 1.0
        self.print_info(f"Buy amount: {amount} contracts")
        self.print_warning("⚠️  Using market orders; trades will fill immediately.")
        
        await self.track_funding("futures_buy_before", self.futures_pair, amount)
        buy_order_id = await self.place_market_order(self.futures_pair, amount, "buy")
        await self.track_funding("futures_buy_after", self.futures_pair, amount)
        
        if not buy_order_id:
            self.print_error("Futures buy failed")
            return False
        
        await asyncio.sleep(2)
        
        # Sell to close the position
        self.print_info(f"Sell amount: {amount} contracts (closing position)")
        await self.track_funding("futures_sell_before", self.futures_pair, amount)
        sell_order_id = await self.place_market_order(self.futures_pair, amount, "sell")
        await self.track_funding("futures_sell_after", self.futures_pair, amount)
        
        if sell_order_id:
            self.print_success("Futures round-trip completed")
            return True
        else:
            self.print_error("Futures sell failed")
            return False
    
    async def test_options_trading(self) -> bool:
        """Test options trading (if an options instrument was found)."""
        self.print_header("TEST 3: Options trading (buy + sell)")
        
        if not self.options_pair:
            self.print_warning("No options pair found, skipping options test")
            return False
        
        price = await self.get_market_price(self.options_pair)
        if not price:
            self.print_warning("Unable to fetch options price; skipping options test")
            return False
        
        # Buy 1 options contract (or 1×contract_size)
        amount = self.options_contract_size if self.options_contract_size else 1.0
        
        self.print_info(f"Buy amount: {amount} contracts")
        self.print_info(f"Current price: ${price:,.4f}")
        self.print_warning("⚠️  Using market orders; trades will fill immediately.")
        
        await self.track_funding("options_buy_before", self.options_pair, amount, price)
        buy_order_id = await self.place_market_order(self.options_pair, amount, "buy")
        await self.track_funding("options_buy_after", self.options_pair, amount, price)
        
        if not buy_order_id:
            self.print_warning("Options buy failed (likely insufficient funds)")
            return False
        
        await asyncio.sleep(2)
        
        # Sell the same number of contracts
        new_price = await self.get_market_price(self.options_pair)
        if new_price:
            price = new_price
        
        await self.track_funding("options_sell_before", self.options_pair, amount, price)
        sell_order_id = await self.place_market_order(self.options_pair, amount, "sell")
        await self.track_funding("options_sell_after", self.options_pair, amount, price)
        
        if sell_order_id:
            self.print_success("Options round-trip completed")
            return True
        else:
            self.print_warning("Options sell failed (maybe no open position)")
            return False
    
    async def cleanup_all_orders(self) -> bool:
        """Cancel all open orders (spot + futures + options)."""
        self.print_header("STEP 4: Cancel all open orders")
        
        try:
            # Cancel all orders for any instrument/currency
            cancel_tool = CancelAllOrdersTool()
            result = await cancel_tool.execute(currency="ETH", kind="any")
            
            if isinstance(result, dict) and result.get("error"):
                self.print_error(f"Failed to cancel all orders: {result.get('error')}")
                return False
            
            self.print_success("All open orders have been cancelled")
            return True
        except Exception as e:
            self.print_error(f"Exception while cancelling orders: {e}")
            return False
    
    async def close_all_positions(self) -> bool:
        """Close all remaining positions."""
        self.print_header("STEP 5: Close all positions")
        
        try:
            positions_tool = GetPositionsTool()
            result = await positions_tool.execute(currency="ETH", kind="any")
            
            if isinstance(result, dict) and result.get("error"):
                self.print_error(f"Failed to query positions: {result.get('error')}")
                return False
            
            positions = result.get("output", []) if isinstance(result, dict) else result
            
            if not positions:
                self.print_success("No positions need to be closed")
                return True
            
            closed = False
            for pos in positions:
                inst_name = pos.get("instrument_name")
                size = pos.get("size", 0)
                direction = pos.get("direction", "")
                
                if abs(size) > 0.0001:  # non-zero position
                    self.print_info(f"Found position: {inst_name} | size: {size} | direction: {direction}")
                    
                    # Close position
                    side = "sell" if size > 0 else "buy"
                    close_amount = abs(size)
                    
                    self.print_info(f"Closing position: {side} {close_amount} {inst_name}")
                    order_id = await self.place_market_order(inst_name, close_amount, side)
                    
                    if order_id:
                        closed = True
                        await asyncio.sleep(2)
            
            if closed:
                self.print_success("All positions have been closed")
            else:
                self.print_success("No positions required closing")
            
            return True
        except Exception as e:
            self.print_error(f"Exception while closing positions: {e}")
            return False
    
    async def convert_all_to_eth(self) -> bool:
        """Convert remaining USDC to ETH via spot market (best-effort)."""
        self.print_header("STEP 6: Convert all assets to ETH")
        
        try:
            # Wait for all trades to settle.
            await asyncio.sleep(3)
            
            # Check USDC balance
            usdc_balance = await self.get_usdc_balance()
            
            if usdc_balance and usdc_balance > 5.0:  # require at least 5 USDC (considering fees)
                if not self.spot_pair:
                    self.print_warning("No spot pair found; cannot convert USDC to ETH")
                    return False
                
                price = await self.get_market_price(self.spot_pair)
                if not price:
                    self.print_warning("Unable to fetch price; skipping conversion")
                    return False
                
                # Use 90% of USDC balance, reserving some for fees.
                usable_usdc = usdc_balance * 0.9
                eth_amount = usable_usdc / price
                
                if self.spot_contract_size:
                    eth_amount = self.adjust_amount_to_contract_size(eth_amount, self.spot_contract_size)
                
                # Ensure the ETH amount does not exceed the affordable maximum.
                max_eth = usable_usdc / price
                if eth_amount > max_eth:
                    eth_amount = max_eth
                    if self.spot_contract_size:
                        eth_amount = self.adjust_amount_to_contract_size(eth_amount, self.spot_contract_size)
                
                self.print_info(f"USDC balance: {usdc_balance:.2f}")
                self.print_info(f"Usable USDC : {usable_usdc:.2f}")
                self.print_info(f"Convert to  : {eth_amount:.6f} ETH")
                
                buy_order_id = await self.place_market_order(self.spot_pair, eth_amount, "buy")
                if buy_order_id:
                    self.print_success("USDC has been converted to ETH")
                    await asyncio.sleep(3)
                    return True
                else:
                    self.print_warning("USDC conversion failed (possibly due to balance/fees)")
                    return False
            else:
                if usdc_balance:
                    self.print_info(f"USDC balance: {usdc_balance:.2f} (too small; skipping conversion)")
                else:
                    self.print_info("No USDC balance")
                return True
        except Exception as e:
            self.print_error(f"Exception while converting assets: {e}")
            return False
    
    async def verify_final_state(self) -> bool:
        """Verify final post-test account state."""
        self.print_header("STEP 7: Verify final state")
        
        # Check final balance
        balance = await self.get_eth_balance()
        if balance:
            self.print_info(f"Final ETH balance: {balance} ETH")
            self.final_eth_balance = balance
            
            if self.initial_eth_balance:
                consumed = self.initial_eth_balance - balance
                self.eth_consumed = consumed
                self.print_info(f"ETH consumed: {consumed:.6f} ETH")
        
        # Check open orders
        orders_tool = GetOpenOrdersTool()
        orders_result = await orders_tool.execute(currency="ETH", kind="any")
        
        open_orders = []
        if isinstance(orders_result, dict) and not orders_result.get("error"):
            open_orders = orders_result.get("output", [])
        
        if open_orders:
            self.print_error(f"There are still {len(open_orders)} open orders")
            for order in open_orders:
                self.print_error(f"  - {order.get('order_id')} | {order.get('instrument_name')}")
            return False
        else:
            self.print_success("No open orders")
        
        # Check positions across a few major currencies.
        active_positions = []
        try:
            for currency in ["ETH", "BTC", "USDC"]:
                try:
                    positions_tool = GetPositionsTool()
                    positions_result = await positions_tool.execute(currency=currency, kind="any")
                    
                    positions = []
                    if isinstance(positions_result, dict) and not positions_result.get("error"):
                        positions = positions_result.get("output", [])
                    
                    for pos in positions:
                        size = abs(pos.get("size", 0))
                        if size > 0.0001:
                            active_positions.append(pos)
                except Exception:
                    continue
        except Exception as e:
            self.print_warning(f"Exception while querying positions: {e}")
        
        if active_positions:
            self.print_error(f"There are still {len(active_positions)} open positions")
            for pos in active_positions:
                self.print_error(f"  - {pos.get('instrument_name')} | size: {pos.get('size')}")
            return False
        else:
            self.print_success("No open positions")
        
        self.print_success(
            "✅ Final state verified: account holds only ETH, with no open orders or positions"
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
        self.print_error(f"Failed trades    : {len(failed)}")
        
        self.print_info(f"\nLog file: {self.log_file}")
    
    async def run_complete_test(self):
        """Run the full multi-asset test: spot, futures, options + cleanup."""
        self.print_header("Comprehensive trading test: spot + futures + options")
        
        self.print_warning("⚠️  This test performs real trades with real funds!")
        self.print_warning(
            "⚠️  After all trades, the account should hold only ETH with no open orders or positions."
        )
        
        # Step 0: get initial balance
        self.print_header("STEP 0: Get initial balance")
        self.initial_eth_balance = await self.get_eth_balance()
        if self.initial_eth_balance:
            self.print_success(f"Initial ETH balance: {self.initial_eth_balance:.6f} ETH")
        else:
            self.print_error("Unable to fetch initial balance")
            return
        
        # Step 1: discover instruments
        if not await self.find_spot_pair():
            return
        
        await self.find_options_pair()  # options leg is optional
        
        await asyncio.sleep(1)
        
        # Step 2: run trading tests
        await self.test_spot_trading()
        await asyncio.sleep(2)
        
        await self.test_futures_trading()
        await asyncio.sleep(2)
        
        await self.test_options_trading()  # optional options leg
        await asyncio.sleep(2)
        
        # Step 3: cleanup
        await self.cleanup_all_orders()
        await asyncio.sleep(2)
        
        await self.close_all_positions()
        await asyncio.sleep(2)
        
        await self.convert_all_to_eth()
        await asyncio.sleep(2)
        
        # Step 4: verification
        await self.verify_final_state()
        
        # Step 5: summary
        await self.print_summary()


async def main():
    test = ComprehensiveTradingTest()
    await test.run_complete_test()


if __name__ == "__main__":
    asyncio.run(main())

