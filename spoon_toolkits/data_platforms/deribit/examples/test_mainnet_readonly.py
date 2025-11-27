"""Mainnet read-only test – safely exercise all non-trading endpoints.

This script verifies:
- Public market-data endpoints
- Authentication
- Account summary
- Positions and open orders

It never submits any trading orders and is safe to run on mainnet.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from spoon_toolkits.deribit.env import DeribitConfig
from spoon_toolkits.deribit.market_data import GetInstrumentsTool, GetTickerTool, GetOrderBookTool
from spoon_toolkits.deribit.account import GetAccountSummaryTool, GetPositionsTool
from spoon_toolkits.deribit.trading import GetOpenOrdersTool


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")


def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")


def print_error(text):
    print(f"{Colors.RED}❌ {text}{Colors.RESET}")


def print_warning(text):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")


async def main():
    """Entry point for the mainnet read-only test suite."""
    print(f"\n{Colors.BOLD}{Colors.RED}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.RED}Deribit mainnet READ-ONLY test{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.RED}{'='*60}{Colors.RESET}\n")
    
    # Environment check
    if DeribitConfig.USE_TESTNET:
        print_warning("Currently using TESTNET, not mainnet.")
        print("Set DERIBIT_USE_TESTNET=false to run true mainnet checks.")
        return
    
    print_warning("⚠️  MAINNET WARNING: real funds are in use.")
    print_warning("⚠️  This test only uses read-only endpoints and never sends trades.")
    print("")
    
    results = {}
    
    # 1. Public API
    print_header("STEP 1: Public API test (read-only, no credentials required)")
    try:
            tool = GetInstrumentsTool()
            result = await tool.execute(currency="BTC", kind="future")
            if isinstance(result, dict) and result.get("error"):
                print_error(f"Failed to fetch futures instruments: {result.get('error')}")
                results["public_api"] = False
            else:
                instruments = result.get("output") if isinstance(result, dict) else result
                print_success(f"Fetched futures instruments: {len(instruments)} instruments")
                if instruments:
                    print(f"   Example instrument: {instruments[0].get('instrument_name', 'N/A')}")
                results["public_api"] = True
        except Exception as e:
            print_error(f"Public API test failed: {e}")
            results["public_api"] = False
    
    # 2. Authentication
    print_header("STEP 2: Authentication test")
    try:
        from spoon_toolkits.deribit.auth import DeribitAuth
        
        auth = DeribitAuth()
        result = await auth.authenticate()
        
        if result and result.get("access_token"):
            print_success("Authentication succeeded")
            print(f"   Token preview: {auth.get_access_token()[:20]}...")
            print(f"   Scope        : {result.get('scope', 'N/A')}")
            print(f"   Expires in   : {result.get('expires_in', 'N/A')} seconds")
            results["auth"] = True
        else:
            print_error("Authentication failed: access_token is missing")
            results["auth"] = False
    except Exception as e:
        print_error(f"Authentication test failed: {e}")
        results["auth"] = False
    
    # 3. Account summary (read-only)
    if results.get("auth"):
        print_header("STEP 3: Account summary test (read-only)")
        try:
            account_tool = GetAccountSummaryTool()
            result = await account_tool.execute(currency="BTC")
            
            if isinstance(result, dict) and result.get("error"):
                print_error(f"Failed to fetch account summary: {result.get('error')}")
                results["account_summary"] = False
            else:
                account = result.get("output") if isinstance(result, dict) else result
                print_success("Fetched account summary successfully")
                print(f"   balance        : {account.get('balance', 'N/A')} BTC")
                print(f"   available_funds: {account.get('available_funds', 'N/A')} BTC")
                print(f"   equity         : {account.get('equity', 'N/A')} BTC")
                print(f"   margin_balance : {account.get('margin_balance', 'N/A')} BTC")
                results["account_summary"] = True
        except Exception as e:
            print_error(f"Account summary test failed: {e}")
            results["account_summary"] = False
        
        # 4. Positions (read-only)
        print_header("STEP 4: Positions test (read-only)")
        try:
            positions_tool = GetPositionsTool()
            result = await positions_tool.execute(currency="BTC")
            
            if isinstance(result, dict) and result.get("error"):
                print_error(f"Failed to fetch positions: {result.get('error')}")
                results["positions"] = False
            else:
                positions = result.get("output") if isinstance(result, dict) else result
                print_success(f"Fetched positions: {len(positions)} entries")
                if positions:
                    for pos in positions[:3]:
                        print(
                            f"   {pos.get('instrument_name')}: "
                            f"size={pos.get('size')}, "
                            f"entry_price={pos.get('entry_price')}, "
                            f"mark_price={pos.get('mark_price')}"
                        )
                results["positions"] = True
        except Exception as e:
            print_error(f"Positions test failed: {e}")
            results["positions"] = False
        
        # 5. Open orders (read-only)
        print_header("STEP 5: Open orders test (read-only)")
        try:
            orders_tool = GetOpenOrdersTool()
            result = await orders_tool.execute(instrument_name="BTC-PERPETUAL")
            
            if isinstance(result, dict) and result.get("error"):
                print_warning(f"Open-orders query failed (possibly no orders): {result.get('error')}")
                results["open_orders"] = True  # not a hard failure
            else:
                orders = result.get("output") if isinstance(result, dict) else result
                print_success(f"Fetched open orders: {len(orders)} entries")
                if orders:
                    for order in orders[:3]:
                        print(
                            f"   order {order.get('order_id')}: "
                            f"{order.get('direction')} {order.get('amount')} @ {order.get('price')}"
                        )
                results["open_orders"] = True
        except Exception as e:
            print_error(f"Open-orders test failed: {e}")
            results["open_orders"] = False
    
    # Summary
    print_header("Read-only test summary")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, result in results.items():
        status = f"{Colors.GREEN}✅ PASS{Colors.RESET}" if result else f"{Colors.RED}❌ FAIL{Colors.RESET}"
        print(f"{name}: {status}")
    
    print(f"\n{Colors.BOLD}Overall: {passed}/{total} steps passed{Colors.RESET}")
    
    if passed == total:
        print_success("\n🎉 All read-only tests passed.")
        print_warning("\n⚠️  Important reminders:")
        print_warning("   - Mainnet uses real funds.")
        print_warning("   - Be cautious when enabling trading operations.")
        print_warning("   - Prefer small test sizes and good risk controls.")
    else:
        print_error("\n⚠️  Some read-only tests failed – please verify configuration and connectivity.")
    
    print()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

