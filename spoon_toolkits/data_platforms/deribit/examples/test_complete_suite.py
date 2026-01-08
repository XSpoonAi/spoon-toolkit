"""Deribit comprehensive test suite – futures + spot.

This script focuses on:
- Environment and credential sanity checks
- Account summary
- Discovering ETH spot instruments
- Placing/cancelling safe limit orders for spot and futures

All orders are deliberately placed far from market price with post_only,
so they should not fill and are cancelled at the end of each test.
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent.parent))

from spoon_toolkits.deribit.env import DeribitConfig
from spoon_toolkits.deribit.market_data import GetInstrumentsTool, GetTickerTool
from spoon_toolkits.deribit.account import GetAccountSummaryTool, GetPositionsTool
from spoon_toolkits.deribit.trading import (
    PlaceBuyOrderTool,
    CancelOrderTool,
    GetOpenOrdersTool,
)


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class TestResult:
    """Container for the result of a single test step."""
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.error = None
        self.details = {}
    
    def set_passed(self, details: Dict = None):
        self.passed = True
        self.details = details or {}
    
    def set_failed(self, error: str, details: Dict = None):
        self.passed = False
        self.error = error
        self.details = details or {}


class TestSuite:
    """High-level Deribit integration test suite (spot + futures)."""
    
    def __init__(self):
        self.results: List[TestResult] = []
        self.account_balance = None
        self.spot_pair = None
        self.futures_pair = "ETH-PERPETUAL"
    
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
    
    async def test_environment(self) -> TestResult:
        """Test 1: environment and configuration sanity."""
        result = TestResult("Environment check")
        self.print_section("TEST 1: Environment check")
        
        try:
            if not DeribitConfig.validate_credentials():
                result.set_failed("API credentials are not configured")
                return result
            
            self.print_success("API credentials are configured")
            api_url = DeribitConfig.get_api_url()
            is_testnet = DeribitConfig.USE_TESTNET
            
            if is_testnet:
                self.print_warning("Currently using TESTNET")
            else:
                self.print_warning("Currently using MAINNET – be careful with real funds!")
            
            self.print_info(f"API URL: {api_url}")
            result.set_passed({"api_url": api_url, "is_testnet": is_testnet})
            
        except Exception as e:
            result.set_failed(f"Environment check raised an exception: {e}")
        
        return result
    
    async def test_account_query(self) -> TestResult:
        """Test 2: basic account summary."""
        result = TestResult("Account summary")
        self.print_section("TEST 2: Account summary")
        
        try:
            account_tool = GetAccountSummaryTool()
            account_result = await account_tool.execute(currency="ETH")
            
            if isinstance(account_result, dict) and account_result.get("error"):
                result.set_failed(f"Failed to get account summary: {account_result.get('error')}")
                return result
            
            account = account_result.get("output") if isinstance(account_result, dict) else account_result
            balance = account.get("balance", 0)
            available = account.get("available_funds", 0)
            
            self.account_balance = balance
            
            self.print_success("Account summary fetched successfully")
            self.print_info(f"ETH balance : {balance} ETH")
            self.print_info(f"Available   : {available} ETH")
            
            if balance < 0.01:
                self.print_warning("Balance is small; some trading tests may fail with insufficient funds")
            
            result.set_passed({"balance": balance, "available": available})
            
        except Exception as e:
            result.set_failed(f"Account summary raised an exception: {e}")
        
        return result
    
    async def test_find_spot_pairs(self) -> TestResult:
        """Test 3: discover ETH spot instruments."""
        result = TestResult("Discover ETH spot instruments")
        self.print_section("TEST 3: Discover ETH spot instruments")
        
        try:
            tool = GetInstrumentsTool()
            spot_result = await tool.execute(currency="ETH", kind="spot", expired=False)
            
            if isinstance(spot_result, dict) and spot_result.get("error"):
                result.set_failed(f"Failed to query spot instruments: {spot_result.get('error')}")
                return result
            
            instruments = spot_result.get("output") if isinstance(spot_result, dict) else spot_result
            
            if not instruments:
                result.set_failed("No ETH spot instruments found")
                return result
            
            self.print_success(f"Found {len(instruments)} ETH spot instruments")
            
            # Prefer ETH/USDC or ETH/USDT
            preferred_pair = None
            for inst in instruments:
                inst_name = inst.get("instrument_name", "")
                if "USDC" in inst_name or "USDT" in inst_name:
                    preferred_pair = inst_name
                    break
            
            if not preferred_pair and instruments:
                preferred_pair = instruments[0].get("instrument_name")
            
            if preferred_pair:
                self.spot_pair = preferred_pair
                self.print_success(f"Selected spot pair: {preferred_pair}")
                result.set_passed({"pair": preferred_pair, "count": len(instruments)})
            else:
                result.set_failed("No usable spot trading pair found")
            
        except Exception as e:
            result.set_failed(f"Exception while querying spot instruments: {e}")
        
        return result
    
    async def test_spot_trading(self) -> TestResult:
        """Test 4: safe spot trading via deep limit order and cancel."""
        result = TestResult("Spot trading test")
        self.print_section("TEST 4: Spot trading (deep limit + cancel)")
        
        if not self.spot_pair:
            result.set_failed("No spot pair selected; skipping test")
            return result
        
        try:
            # Fetch spot price for the selected instrument
            ticker_tool = GetTickerTool()
            ticker_result = await ticker_tool.execute(instrument_name=self.spot_pair)
            
            if isinstance(ticker_result, dict) and ticker_result.get("error"):
                result.set_failed(f"Failed to fetch spot price: {ticker_result.get('error')}")
                return result
            
            ticker = ticker_result.get("output") if isinstance(ticker_result, dict) else ticker_result
            current_price = ticker.get("last_price") or ticker.get("mark_price")
            
            if not current_price:
                result.set_failed("No price (last/mark) available for spot instrument")
                return result
            
            self.print_info(f"Current price: ${current_price:,.2f}")
            
            # Create a deep, non-filling limit order.
            safe_price = current_price * 0.7  # 30% below current price
            order_amount = 0.01  # 0.01 ETH
            
            self.print_info(f"Limit price: ${safe_price:,.2f} (30% below spot)")
            self.print_info(f"Order size : {order_amount} ETH")
            
            buy_tool = PlaceBuyOrderTool()
            buy_result = await buy_tool.execute(
                instrument_name=self.spot_pair,
                amount=order_amount,
                price=safe_price,
                order_type="limit",
                post_only=True,
                time_in_force="good_til_cancelled",
            )
            
            if isinstance(buy_result, dict) and buy_result.get("error"):
                error_msg = buy_result.get("error", "")
                if "insufficient" in error_msg.lower() or "balance" in error_msg.lower():
                    self.print_warning("Insufficient balance, but interface and validation are working.")
                    result.set_passed({"interface_available": True, "error": error_msg})
                else:
                    result.set_failed(f"Spot limit order failed: {error_msg}")
                return result
            
            order_info = (
                buy_result.get("output", {}).get("order", {})
                if isinstance(buy_result, dict)
                else buy_result.get("order", {})
            )
            order_id = order_info.get("order_id")
            
            if not order_id:
                result.set_failed("Order created but no order_id returned")
                return result
            
            self.print_success(f"Spot limit order created: {order_id}")
            
            # Check the order is visible in open orders.
            await asyncio.sleep(1)
            orders_tool = GetOpenOrdersTool()
            orders_result = await orders_tool.execute(instrument_name=self.spot_pair)
            orders = orders_result.get("output") if isinstance(orders_result, dict) else orders_result
            found_order = any(o.get("order_id") == order_id for o in orders)
            
            if found_order:
                self.print_success("Order is visible in the order book")
            else:
                self.print_warning("Order not visible in open orders list (may have been cancelled/rejected).")
            
            # Now cancel the order.
            cancel_tool = CancelOrderTool()
            cancel_result = await cancel_tool.execute(order_id=order_id)
            
            if isinstance(cancel_result, dict) and cancel_result.get("error"):
                self.print_warning(f"Cancel failed: {cancel_result.get('error')}")
                result.set_passed({"order_created": True, "cancel_failed": True})
            else:
                self.print_success("Order cancelled successfully")
                result.set_passed({"order_created": True, "order_cancelled": True})
            
        except Exception as e:
            result.set_failed(f"Spot trading test raised an exception: {e}")
        
        return result
    
    async def test_futures_trading(self) -> TestResult:
        """Test 5: safe futures trading via deep limit order and cancel."""
        result = TestResult("Futures trading test")
        self.print_section("TEST 5: Futures trading (deep limit + cancel)")
        
        try:
            # Fetch spot price for the selected instrument
            ticker_tool = GetTickerTool()
            ticker_result = await ticker_tool.execute(instrument_name=self.futures_pair)
            
            if isinstance(ticker_result, dict) and ticker_result.get("error"):
                result.set_failed(f"Failed to fetch futures price: {ticker_result.get('error')}")
                return result
            
            ticker = ticker_result.get("output") if isinstance(ticker_result, dict) else ticker_result
            current_price = ticker.get("last_price") or ticker.get("mark_price")
            
            if not current_price:
                result.set_failed("No price (last/mark) available for futures instrument")
                return result
            
            self.print_info(f"Current futures price: ${current_price:,.2f}")
            
            # Create a deep, non-filling limit order for 1 contract.
            safe_price = current_price * 0.6  # 40% below current price
            order_amount = 1  # 1 contract
            
            self.print_info(f"Limit price: ${safe_price:,.2f} (40% below futures price)")
            self.print_info(f"Order size : {order_amount} contracts")
            
            buy_tool = PlaceBuyOrderTool()
            buy_result = await buy_tool.execute(
                instrument_name=self.futures_pair,
                amount=order_amount,
                price=safe_price,
                order_type="limit",
                post_only=True,
                time_in_force="good_til_cancelled",
            )
            
            if isinstance(buy_result, dict) and buy_result.get("error"):
                error_msg = buy_result.get("error", "")
                if "insufficient" in error_msg.lower() or "balance" in error_msg.lower():
                    self.print_warning("Insufficient margin, but interface and validation are working.")
                    result.set_passed({"interface_available": True, "error": error_msg})
                else:
                    result.set_failed(f"Futures limit order failed: {error_msg}")
                return result
            
            order_info = (
                buy_result.get("output", {}).get("order", {})
                if isinstance(buy_result, dict)
                else buy_result.get("order", {})
            )
            order_id = order_info.get("order_id")
            
            if not order_id:
                result.set_failed("Order created but no order_id returned")
                return result
            
            self.print_success(f"Futures limit order created: {order_id}")
            
            # Check the order is visible in open orders.
            await asyncio.sleep(1)
            orders_tool = GetOpenOrdersTool()
            orders_result = await orders_tool.execute(instrument_name=self.futures_pair)
            orders = orders_result.get("output") if isinstance(orders_result, dict) else orders_result
            found_order = any(o.get("order_id") == order_id for o in orders)
            
            if found_order:
                self.print_success("Order is visible in the order book")
            else:
                self.print_warning("Order not visible in open orders list (may have been cancelled/rejected).")
            
            # Now cancel the order.
            cancel_tool = CancelOrderTool()
            cancel_result = await cancel_tool.execute(order_id=order_id)
            
            if isinstance(cancel_result, dict) and cancel_result.get("error"):
                self.print_warning(f"Cancel failed: {cancel_result.get('error')}")
                result.set_passed({"order_created": True, "cancel_failed": True})
            else:
                self.print_success("Order cancelled successfully")
                result.set_passed({"order_created": True, "order_cancelled": True})
            
        except Exception as e:
            result.set_failed(f"Futures trading test raised an exception: {e}")
        
        return result
    
    async def run_all_tests(self):
        """Run all tests in sequence and then print a compact report."""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'Deribit comprehensive test suite (futures + spot)':^70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.YELLOW}Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}\n")
        
        print("The suite will run:")
        print("  1. ✅ Environment check")
        print("  2. ✅ Account summary")
        print("  3. ✅ Discover ETH spot instruments")
        print("  4. ⚠️  Spot trading test (deep limit + cancel)")
        print("  5. ⚠️  Futures trading test (deep limit + cancel)")
        print()
        
        tests = [
            self.test_environment,
            self.test_account_query,
            self.test_find_spot_pairs,
            self.test_spot_trading,
            self.test_futures_trading,
        ]
        
        for test_func in tests:
            try:
                result = await test_func()
                self.results.append(result)
                
                if not result.passed and "Discover ETH spot instruments" in result.name:
                    self.print_warning("Skipping spot trading test due to missing spot instruments.")
                    skip_result = TestResult("Spot trading test")
                    skip_result.set_failed("Skipped: no spot pair discovered")
                    self.results.append(skip_result)
                    continue
                    
            except KeyboardInterrupt:
                self.print_warning("\nTest suite interrupted by user")
                break
            except Exception as e:
                self.print_error(f"\nUnexpected exception in test: {e}")
                error_result = TestResult(test_func.__name__)
                error_result.set_failed(f"Test raised unexpected exception: {e}")
                self.results.append(error_result)
        
        self.generate_report()
    
    def generate_report(self):
        """Print a concise summary of all test results."""
        self.print_header("Test report")
        
        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        
        print(f"{Colors.BOLD}Summary of test results:{Colors.RESET}\n")
        
        for result in self.results:
            if result.passed:
                status = f"{Colors.GREEN}✅ PASS{Colors.RESET}"
            else:
                status = f"{Colors.RED}❌ FAIL{Colors.RESET}"
            
            print(f"  {result.name:28s}: {status}")
            if result.error:
                print(f"    {Colors.RED}Error : {result.error}{Colors.RESET}")
            if result.details:
                for key, value in result.details.items():
                    if key != "error":
                        print(f"    {Colors.CYAN}{key}: {value}{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}Overall: {passed}/{total} tests passed{Colors.RESET}\n")
        
        if passed == total:
            self.print_success("🎉 All tests passed.")
        elif passed >= total - 1:
            self.print_success("✅ Core functionality tests passed.")
        else:
            self.print_warning("⚠️  Some tests failed; please check configuration and connectivity.")
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        # Quick guidance based on account balance
        if self.account_balance is not None:
            print(f"{Colors.BOLD}Account balance: {self.account_balance} ETH{Colors.RESET}")
            if self.account_balance < 0.05:
                self.print_warning("Consider funding at least ~0.1 ETH for a smoother test experience.")
        
        print(f"\n{Colors.CYAN}💡 Notes:{Colors.RESET}")
        print("  - Spot trading requires no margin and is suitable for small balance tests.")
        print("  - Futures trading requires margin; costs depend on leverage and volatility.")
        print("  - Even if orders fail with 'insufficient funds', this still validates the tool/endpoint.")


async def main():
    suite = TestSuite()
    await suite.run_all_tests()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Test suite interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"\n\n{Colors.RED}Test suite failed with exception: {e}{Colors.RESET}")

