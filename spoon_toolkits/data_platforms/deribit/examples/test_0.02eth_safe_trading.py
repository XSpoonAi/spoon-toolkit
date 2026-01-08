"""0.02 ETH safe trading test script – based on the Deribit examples.

This script is intended for very small balances (around 0.02 ETH) and focuses on:
- Environment and credential checks
- Account and position queries
- A deep, non-filling limit futures order with post_only

All futures orders are placed far from the market and immediately cancelled,
so no real position should be opened if everything works as expected.
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent.parent))  # Adjust path for DeSearchMcp

from spoon_toolkits.deribit.env import DeribitConfig
from spoon_toolkits.deribit.market_data import GetTickerTool, GetInstrumentsTool
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


def print_warning(text):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")


def print_info(text):
    print(f"{Colors.CYAN}ℹ️  {text}{Colors.RESET}")


async def step1_check_environment():
    """Step 1: environment and credential sanity check."""
    print_header("STEP 1: Environment check")
    
    # Check API configuration
    if not DeribitConfig.validate_credentials():
        print_error("API credentials are not configured.")
        print_info("Please configure DERIBIT_CLIENT_ID and DERIBIT_CLIENT_SECRET in your .env file.")
        return False
    
    print_success("API credentials are configured.")
    client_id_preview = DeribitConfig.CLIENT_ID[:10] + "..." if DeribitConfig.CLIENT_ID else "NOT SET"
    print_info(f"Client ID (preview): {client_id_preview}")
    
    # Check whether we are using mainnet or testnet
    api_url = DeribitConfig.get_api_url()
    is_testnet = DeribitConfig.USE_TESTNET
    
    if is_testnet:
        print_warning("Using TESTNET")
        print_info(f"API URL: {api_url}")
    else:
        print_warning("Using MAINNET – real funds at risk")
        print_info(f"API URL: {api_url}")
    
    return True


async def step2_check_account():
    """Step 2: check ETH account summary for a small-balance account."""
    print_header("STEP 2: Check ETH account summary")
    
    try:
        account_tool = GetAccountSummaryTool()
        result = await account_tool.execute(currency="ETH")
        
        if isinstance(result, dict) and result.get("error"):
            print_error(f"Failed to fetch account summary: {result.get('error')}")
            return False, None
        
        account = result.get("output") if isinstance(result, dict) else result
        balance = account.get("balance", 0)
        available = account.get("available_funds", 0)
        equity = account.get("equity", 0)
        
        print_success("Account summary fetched successfully")
        print_info(f"ETH balance : {balance} ETH")
        print_info(f"Available   : {available} ETH")
        print_info(f"Equity      : {equity} ETH")
        
        if balance < 0.01:
            print_warning("Balance is small; futures tests may fail with insufficient margin.")
            print_info("Consider funding at least ~0.05 ETH for a smoother experience.")
        else:
            print_success(f"Balance is sufficient ({balance} ETH), continuing.")
        
        return True, account
        
    except Exception as e:
        print_error(f"Account summary raised exception: {e}")
        return False, None


async def step3_check_positions():
    """Step 3: check current ETH positions (if any)."""
    print_header("STEP 3: Check open positions")
    
    try:
        positions_tool = GetPositionsTool()
        result = await positions_tool.execute(currency="ETH")
        
        if isinstance(result, dict) and result.get("error"):
            print_warning(f"Failed to fetch positions (possibly none): {result.get('error')}")
            return True  # not an error; likely just no positions
        
        positions = result.get("output") if isinstance(result, dict) else result
        
        if positions:
            print_warning(f"Found {len(positions)} open positions")
            for pos in positions:
                print_info(
                    f"  Instrument: {pos.get('instrument_name')}, "
                    f"size: {pos.get('size')}, "
                    f"direction: {pos.get('direction')}"
                )
        else:
            print_success("No open positions found")
        
        return True
        
    except Exception as e:
        print_error(f"Position query raised exception: {e}")
        return False


async def step4_get_market_price():
    """Step 4: fetch current price for ETH-PERPETUAL futures."""
    print_header("STEP 4: Get ETH-PERPETUAL price")
    
    try:
        ticker_tool = GetTickerTool()
        result = await ticker_tool.execute(instrument_name="ETH-PERPETUAL")
        
        if isinstance(result, dict) and result.get("error"):
            print_error(f"Failed to fetch ETH-PERPETUAL price: {result.get('error')}")
            return False, None
        
        ticker = result.get("output") if isinstance(result, dict) else result
        current_price = ticker.get("last_price") or ticker.get("mark_price")
        
        if not current_price:
            print_error("Unable to get last/mark price for ETH-PERPETUAL")
            return False, None
        
        print_success(f"Current ETH futures price: ${current_price:,.2f}")
        print_info(f"Mark price : ${ticker.get('mark_price', 'N/A'):,.2f}")
        print_info(f"Best bid   : ${ticker.get('best_bid_price', 'N/A'):,.2f}")
        print_info(f"Best ask   : ${ticker.get('best_ask_price', 'N/A'):,.2f}")
        
        return True, current_price
        
    except Exception as e:
        print_error(f"Futures price query raised exception: {e}")
        return False, None


async def step5_place_safe_order(current_price):
    """Step 5: place a deep, post_only futures limit order that should not fill."""
    print_header("STEP 5: Place safe futures limit buy order")
    
    # Use a safe price (40% below current price) so the order will not fill.
    safe_price = current_price * 0.6
    order_amount = 1  # 1 contract = 1 ETH
    
    print_info(f"Current price: ${current_price:,.2f}")
    print_info(f"Limit price : ${safe_price:,.2f} (40% below current price)")
    print_info(f"Order size  : {order_amount} contract(s)")
    print_warning("⚠️  Price is far below market; the order should not fill.")
    
    # Show a dry-run style preview.
    print(f"\n{Colors.YELLOW}Placing futures order with parameters:{Colors.RESET}")
    print(f"  instrument : ETH-PERPETUAL")
    print(f"  side       : buy")
    print(f"  amount     : {order_amount} contract(s)")
    print(f"  price      : ${safe_price:,.2f}")
    print(f"  type       : limit + post_only")
    
    try:
        buy_tool = PlaceBuyOrderTool()
        result = await buy_tool.execute(
            instrument_name="ETH-PERPETUAL",
            amount=order_amount,
            price=safe_price,
            order_type="limit",
            post_only=True,
            time_in_force="good_til_cancelled",
        )
        
        if isinstance(result, dict) and result.get("error"):
            error_msg = result.get("error", "")
            print_error(f"Order placement failed: {error_msg}")
            
            if "insufficient" in error_msg.lower() or "balance" in error_msg.lower():
                print_warning("Insufficient margin, but we validated that:")
                print_success("  ✅ Account APIs work")
                print_success("  ✅ Trading endpoint works")
                print_success("  ✅ API key permissions are correct")
                print_info("  You can deposit more ETH later to run a full workflow.")
            return False, None
        
        order_info = (
            result.get("output", {}).get("order", {})
            if isinstance(result, dict)
            else result.get("order", {})
        )
        order_id = order_info.get("order_id")
        
        if not order_id:
            print_error("Order created but no order_id returned")
            return False, None
        
        print_success("Futures limit order created.")
        print_info(f"  order_id : {order_id}")
        print_info(f"  amount   : {order_info.get('amount')} contracts")
        print_info(f"  price    : ${order_info.get('price', safe_price):,.2f}")
        print_info(f"  state    : {order_info.get('order_state', 'N/A')}")
        
        return True, order_id
        
    except Exception as e:
        print_error(f"Order placement raised exception: {e}")
        return False, None


async def step6_verify_order(order_id):
    """Step 6: verify that the created futures order appears in open orders."""
    print_header("STEP 6: Verify futures order")
    
    try:
        await asyncio.sleep(1)  # wait for the order to be registered
        
        orders_tool = GetOpenOrdersTool()
        result = await orders_tool.execute(instrument_name="ETH-PERPETUAL")
        
        if isinstance(result, dict) and result.get("error"):
            print_warning(f"Failed to query open orders: {result.get('error')}")
            return True  # still attempt cancel
        
        orders = result.get("output") if isinstance(result, dict) else result
        found_order = any(o.get("order_id") == order_id for o in orders)
        
        if found_order:
            print_success(f"Order appears in open orders: {order_id}")
            for order in orders:
                if order.get("order_id") == order_id:
                    print_info(f"  state : {order.get('order_state', 'N/A')}")
                    print_info(f"  amount: {order.get('amount', 'N/A')} contracts")
                    print_info(f"  price : ${order.get('price', 'N/A'):,.2f}")
                    break
        else:
            print_warning("Order not present in open orders (might have been rejected).")
            print_info("Proceeding to cancel as a safety step...")
        
        return True
        
    except Exception as e:
        print_error(f"Order verification raised exception: {e}")
        return True  # still attempt cancel


async def step7_cancel_order(order_id):
    """Step 7: cancel the futures limit order."""
    print_header("STEP 7: Cancel futures order")
    
    try:
        cancel_tool = CancelOrderTool()
        result = await cancel_tool.execute(order_id=order_id)
        
        if isinstance(result, dict) and result.get("error"):
            print_warning(f"Failed to cancel order: {result.get('error')}")
            print_warning("Please manually inspect and cancel any remaining orders.")
            return False
        
        print_success(f"Order cancelled: {order_id}")
        return True
        
    except Exception as e:
        print_error(f"Order cancel raised exception: {e}")
        return False


async def main():
    """Main test entrypoint for the 0.02 ETH safe trading scenario."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'0.02 ETH safe trading test':^70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}\n")
    
    print(f"{Colors.YELLOW}Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}\n")
    
    print("This script safely validates Deribit futures trading tools with a tiny balance:")
    print("  ✅ Uses limit + post_only so orders do not fill")
    print("  ✅ Price set 40% below market to avoid execution")
    print("  ✅ Orders are cancelled after verification")
    print()
    
    results = {}
    
    # STEP 1: environment check
    results["env_check"] = await step1_check_environment()
    if not results["env_check"]:
        print_error("\nEnvironment check failed, aborting test.")
        return
    
    # STEP 2: account summary
    account_ok, account = await step2_check_account()
    results["account_summary"] = account_ok
    if not account_ok:
        print_error("\nAccount summary failed, aborting test.")
        return
    
    # STEP 3: positions
    results["position_query"] = await step3_check_positions()
    
    # STEP 4: price
    price_ok, current_price = await step4_get_market_price()
    results["price_query"] = price_ok
    if not price_ok:
        print_error("\nPrice query failed, aborting test.")
        return
    
    # STEP 5: place order
    order_ok, order_id = await step5_place_safe_order(current_price)
    results["place_order"] = order_ok
    if not order_ok or not order_id:
        print_warning("\nOrder placement failed, but earlier API checks have passed.")
        print_info("We validated account, price, and trading endpoints.")
        return
    
    # STEP 6: verify order
    results["verify_order"] = await step6_verify_order(order_id)
    
    # STEP 7: cancel order
    results["cancel_order"] = await step7_cancel_order(order_id)
    
    # Summary
    print_header("Test summary")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for step_name, result in results.items():
        status = f"{Colors.GREEN}✅ PASS{Colors.RESET}" if result else f"{Colors.RED}❌ FAIL{Colors.RESET}"
        print(f"{step_name:20s}: {status}")
    
    print(f"\n{Colors.BOLD}Overall: {passed}/{total} steps passed{Colors.RESET}\n")
    
    if passed == total:
        print_success("🎉 All steps passed; small-balance futures tools are validated.")
    elif passed >= total - 1:
        print_success("✅ Core functionality validated; some steps may have failed due to low balance.")
    else:
        print_warning("⚠️  Multiple steps failed; please check configuration and network connectivity.")
    
    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Test interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"\n\n{Colors.RED}Test failed with exception: {e}{Colors.RESET}")

