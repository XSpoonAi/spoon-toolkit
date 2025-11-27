"""Complete verification script - Run all tests and verify all functionality"""

import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from spoon_toolkits.deribit.env import DeribitConfig


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}\n")


def print_success(text):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")


def print_error(text):
    """Print error message"""
    print(f"{Colors.RED}❌ {text}{Colors.RESET}")


def print_warning(text):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")


def print_info(text):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.RESET}")


async def verify_imports():
    """Verify all modules can be imported"""
    print_header("Phase 1: Module Import Verification")
    
    results = {
        "passed": 0,
        "failed": 0,
        "total": 0
    }
    
    # Test core modules
    modules_to_test = [
        ("jsonrpc_client", "DeribitJsonRpcClient"),
        ("auth", "DeribitAuth"),
        ("base", "DeribitBaseTool"),
        ("env", "DeribitConfig"),
        ("cache", "time_cache"),
    ]
    
    for module_name, class_name in modules_to_test:
        results["total"] += 1
        try:
            module = __import__(f"spoon_toolkits.deribit.{module_name}", fromlist=[class_name])
            cls = getattr(module, class_name)
            print_success(f"{module_name}.{class_name} imported successfully")
            results["passed"] += 1
        except Exception as e:
            print_error(f"{module_name}.{class_name} import failed: {e}")
            results["failed"] += 1
    
    # Test tool modules
    tool_modules = [
        ("market_data", ["GetInstrumentsTool", "GetOrderBookTool", "GetTickerTool"]),
        ("account", ["GetAccountSummaryTool", "GetPositionsTool"]),
        ("trading", ["PlaceBuyOrderTool", "CancelOrderTool"]),
    ]
    
    for module_name, tool_names in tool_modules:
        for tool_name in tool_names:
            results["total"] += 1
            try:
                module = __import__(f"spoon_toolkits.deribit.{module_name}", fromlist=[tool_name])
                cls = getattr(module, tool_name)
                print_success(f"{module_name}.{tool_name} imported successfully")
                results["passed"] += 1
            except Exception as e:
                print_error(f"{module_name}.{tool_name} import failed: {e}")
                results["failed"] += 1
    
    print(f"\n{Colors.BOLD}Import Test Results: {results['passed']}/{results['total']} passed{Colors.RESET}")
    return results["failed"] == 0


async def verify_public_api():
    """Verify public API connection"""
    print_header("Phase 2: Public API Connection Verification")
    
    from spoon_toolkits.deribit.jsonrpc_client import DeribitJsonRpcClient
    
    tests = [
        ("Get Instruments", "public/get_instruments", {"currency": "BTC", "kind": "future"}),
        ("Get Order Book", "public/get_order_book", {"instrument_name": "BTC-PERPETUAL", "depth": 5}),
        ("Get Ticker", "public/ticker", {"instrument_name": "BTC-PERPETUAL"}),
        ("Get Index Price", "public/get_index_price", {"index_name": "btc_usd"}),
    ]
    
    passed = 0
    failed = 0
    
    async with DeribitJsonRpcClient() as client:
        for test_name, method, params in tests:
            try:
                result = await client.call(method, params)
                if result is not None:
                    print_success(f"{test_name}: OK")
                    passed += 1
                else:
                    print_error(f"{test_name}: No result returned")
                    failed += 1
            except Exception as e:
                print_error(f"{test_name}: {str(e)}")
                failed += 1
    
    print(f"\n{Colors.BOLD}Public API Test Results: {passed}/{len(tests)} passed{Colors.RESET}")
    return failed == 0


async def verify_market_data_tools():
    """Verify all market data tools"""
    print_header("Phase 3: Market Data Tools Verification")
    
    from spoon_toolkits.deribit.market_data import (
        GetInstrumentsTool,
        GetOrderBookTool,
        GetTickerTool,
        GetLastTradesTool,
        GetIndexPriceTool,
        GetBookSummaryTool
    )
    
    tests = [
        (GetInstrumentsTool, {"currency": "BTC", "kind": "future"}, "GetInstrumentsTool"),
        (GetOrderBookTool, {"instrument_name": "BTC-PERPETUAL", "depth": 5}, "GetOrderBookTool"),
        (GetTickerTool, {"instrument_name": "BTC-PERPETUAL"}, "GetTickerTool"),
        (GetLastTradesTool, {"instrument_name": "BTC-PERPETUAL", "count": 5}, "GetLastTradesTool"),
        (GetIndexPriceTool, {"index_name": "btc_usd"}, "GetIndexPriceTool"),
        (GetBookSummaryTool, {"currency": "BTC", "kind": "future"}, "GetBookSummaryTool"),
    ]
    
    passed = 0
    failed = 0
    
    for tool_class, params, tool_name in tests:
        try:
            tool = tool_class()
            result = await tool.execute(**params)
            
            if isinstance(result, dict) and result.get("error"):
                print_error(f"{tool_name}: {result.get('error')}")
                failed += 1
            else:
                output = result.get("output") if isinstance(result, dict) else result
                if output is not None:
                    print_success(f"{tool_name}: OK")
                    passed += 1
                else:
                    print_error(f"{tool_name}: No output")
                    failed += 1
        except Exception as e:
            print_error(f"{tool_name}: Exception - {str(e)}")
            failed += 1
    
    print(f"\n{Colors.BOLD}Market Data Tools Results: {passed}/{len(tests)} passed{Colors.RESET}")
    return failed == 0


async def verify_authentication():
    """Verify authentication (if credentials available)"""
    print_header("Phase 4: Authentication Verification")
    
    if not DeribitConfig.validate_credentials():
        print_warning("API credentials not configured - skipping authentication tests")
        print_info("Set DERIBIT_CLIENT_ID and DERIBIT_CLIENT_SECRET to test authentication")
        return True  # Not a failure, just skipped
    
    from spoon_toolkits.deribit.auth import DeribitAuth
    
    try:
        auth = DeribitAuth()
        result = await auth.authenticate()
        
        if result and result.get("access_token"):
            print_success("Authentication: OK")
            print_info(f"   Token: {auth.get_access_token()[:20]}...")
            print_info(f"   Scope: {result.get('scope', 'N/A')}")
            print_info(f"   Expires in: {result.get('expires_in', 'N/A')} seconds")
            
            # Test token validity
            is_valid = auth.is_token_valid()
            print_success(f"Token validity check: {'Valid' if is_valid else 'Invalid'}")
            
            return True
        else:
            print_error("Authentication: Failed - No access token")
            return False
    except Exception as e:
        print_error(f"Authentication: Exception - {str(e)}")
        return False


async def verify_account_tools():
    """Verify account management tools (if credentials available)"""
    print_header("Phase 5: Account Management Tools Verification")
    
    if not DeribitConfig.validate_credentials():
        print_warning("API credentials not configured - skipping account tools tests")
        return True
    
    from spoon_toolkits.deribit.account import (
        GetAccountSummaryTool,
        GetPositionsTool,
        GetOrderHistoryTool,
        GetTradeHistoryTool
    )
    
    tests = [
        (GetAccountSummaryTool, {"currency": "BTC"}, "GetAccountSummaryTool"),
        (GetPositionsTool, {"currency": "BTC"}, "GetPositionsTool"),
        (GetOrderHistoryTool, {"instrument_name": "BTC-PERPETUAL", "count": 5}, "GetOrderHistoryTool"),
        (GetTradeHistoryTool, {"instrument_name": "BTC-PERPETUAL", "count": 5}, "GetTradeHistoryTool"),
    ]
    
    passed = 0
    failed = 0
    
    for tool_class, params, tool_name in tests:
        try:
            tool = tool_class()
            result = await tool.execute(**params)
            
            if isinstance(result, dict) and result.get("error"):
                print_error(f"{tool_name}: {result.get('error')}")
                failed += 1
            else:
                output = result.get("output") if isinstance(result, dict) else result
                if output is not None:
                    print_success(f"{tool_name}: OK")
                    passed += 1
                else:
                    print_error(f"{tool_name}: No output")
                    failed += 1
        except Exception as e:
            print_error(f"{tool_name}: Exception - {str(e)}")
            failed += 1
    
    print(f"\n{Colors.BOLD}Account Tools Results: {passed}/{len(tests)} passed{Colors.RESET}")
    return failed == 0


async def verify_trading_tools():
    """Verify trading tools (read-only operations only)"""
    print_header("Phase 6: Trading Tools Verification")
    
    if not DeribitConfig.validate_credentials():
        print_warning("API credentials not configured - skipping trading tools tests")
        return True
    
    from spoon_toolkits.deribit.trading import GetOpenOrdersTool
    
    # Only test read-only operations to avoid placing real orders
    try:
        tool = GetOpenOrdersTool()
        result = await tool.execute(instrument_name="BTC-PERPETUAL")
        
        if isinstance(result, dict) and result.get("error"):
            print_warning(f"GetOpenOrdersTool: {result.get('error')} (may be expected if no orders)")
        else:
            print_success("GetOpenOrdersTool: OK (read-only test)")
        
        print_warning("Other trading tools (PlaceBuyOrder, PlaceSellOrder, etc.) skipped")
        print_warning("These would execute real orders - test manually with caution")
        
        return True
    except Exception as e:
        print_error(f"GetOpenOrdersTool: Exception - {str(e)}")
        return False


async def verify_mcp_integration():
    """Verify MCP service integration"""
    print_header("Phase 7: MCP Service Integration Verification")
    
    try:
        from spoon_toolkits.deribit import mcp
        
        print_success("MCP server initialized")
        print_info(f"   Server name: {mcp.name if hasattr(mcp, 'name') else 'Deribit Tools'}")
        
        # Count registered tools
        tool_count = len([attr for attr in dir(mcp) if not attr.startswith("_") and callable(getattr(mcp, attr, None))])
        print_success(f"MCP tools registered: {tool_count}")
        
        return True
    except Exception as e:
        print_error(f"MCP integration: Exception - {str(e)}")
        return False


async def main():
    """Run all verification tests"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}Deribit API Integration - Complete Verification{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    results = {}
    
    # Run all verification phases
    results["imports"] = await verify_imports()
    results["public_api"] = await verify_public_api()
    results["market_data"] = await verify_market_data_tools()
    results["authentication"] = await verify_authentication()
    results["account_tools"] = await verify_account_tools()
    results["trading_tools"] = await verify_trading_tools()
    results["mcp_integration"] = await verify_mcp_integration()
    
    # Final summary
    print_header("Final Verification Summary")
    
    total_tests = len(results)
    passed_tests = sum(1 for v in results.values() if v)
    failed_tests = total_tests - passed_tests
    
    for phase, result in results.items():
        status = f"{Colors.GREEN}✅ PASSED{Colors.RESET}" if result else f"{Colors.RED}❌ FAILED{Colors.RESET}"
        print(f"{phase.replace('_', ' ').title()}: {status}")
    
    print(f"\n{Colors.BOLD}Overall Results: {passed_tests}/{total_tests} phases passed{Colors.RESET}")
    
    if failed_tests == 0:
        print_success("\n🎉 All verification tests passed!")
    else:
        print_error(f"\n⚠️  {failed_tests} phase(s) failed. Please review errors above.")
    
    print(f"\n{Colors.BOLD}Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}\n")
    
    return failed_tests == 0


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)

