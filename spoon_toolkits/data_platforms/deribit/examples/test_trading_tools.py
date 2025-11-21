"""Test trading tools (requires authentication)"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from spoon_toolkits.deribit.env import DeribitConfig
from spoon_toolkits.deribit.trading import (
    PlaceBuyOrderTool,
    PlaceSellOrderTool,
    CancelOrderTool,
    CancelAllOrdersTool,
    GetOpenOrdersTool,
    EditOrderTool
)


async def test_trading_tools():
    """Test all trading tools"""
    print("=" * 60)
    print("Testing Trading Tools")
    print("=" * 60)
    
    # Check credentials
    if not DeribitConfig.validate_credentials():
        print("❌ Error: API credentials not configured!")
        print("   Trading tools require authentication.")
        print("   Please set DERIBIT_CLIENT_ID and DERIBIT_CLIENT_SECRET")
        return
    
    print(f"✅ Credentials found")
    print(f"   Using {'Testnet' if DeribitConfig.USE_TESTNET else 'Mainnet'}")
    print("\n⚠️  WARNING: Trading tools will execute real orders!")
    print("   Make sure you are using Testnet for testing.")
    print("   Press Ctrl+C to cancel, or wait 5 seconds to continue...")
    
    try:
        await asyncio.sleep(5)
    except KeyboardInterrupt:
        print("\n❌ Test cancelled by user")
        return
    
    tools_tested = 0
    tools_passed = 0
    
    # Test 1: GetOpenOrdersTool (read-only, safe to test)
    print("\n[Test 1] GetOpenOrdersTool")
    tools_tested += 1
    try:
        tool = GetOpenOrdersTool()
        result = await tool.execute(instrument_name="ETH-PERPETUAL")
        if isinstance(result, dict) and result.get("error"):
            print(f"❌ Failed: {result.get('error')}")
        else:
            output = result.get("output") if isinstance(result, dict) else result
            orders = output if isinstance(output, list) else []
            print(f"✅ Success! Found {len(orders)} open orders")
            tools_passed += 1
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # Test 2: PlaceBuyOrderTool (WARNING: This will place a real order!)
    print("\n[Test 2] PlaceBuyOrderTool")
    print("⚠️  SKIPPED: This would place a real order. Test manually with caution.")
    tools_tested += 1
    # Uncomment to test (USE WITH CAUTION):
    # tool = PlaceBuyOrderTool()
    # result = await tool.execute(
    #     instrument_name="BTC-PERPETUAL",
    #     amount=0.001,
    #     price=50000,
    #     order_type="limit"
    # )
    
    # Test 3: PlaceSellOrderTool (WARNING: This will place a real order!)
    print("\n[Test 3] PlaceSellOrderTool")
    print("⚠️  SKIPPED: This would place a real order. Test manually with caution.")
    tools_tested += 1
    
    # Test 4: CancelOrderTool (WARNING: This will cancel a real order!)
    print("\n[Test 4] CancelOrderTool")
    print("⚠️  SKIPPED: This would cancel a real order. Test manually with caution.")
    tools_tested += 1
    
    # Test 5: CancelAllOrdersTool (WARNING: This will cancel all orders!)
    print("\n[Test 5] CancelAllOrdersTool")
    print("⚠️  SKIPPED: This would cancel all orders. Test manually with caution.")
    tools_tested += 1
    
    # Test 6: EditOrderTool (WARNING: This will edit a real order!)
    print("\n[Test 6] EditOrderTool")
    print("⚠️  SKIPPED: This would edit a real order. Test manually with caution.")
    tools_tested += 1
    
    # Summary
    print("\n" + "=" * 60)
    print(f"Trading Tools Test Summary: {tools_passed}/{tools_tested} passed")
    print("=" * 60)
    print("\nNote: Most trading tools are skipped to prevent accidental orders.")
    print("To test trading tools:")
    print("1. Ensure you are on Testnet (DERIBIT_USE_TESTNET=true)")
    print("2. Uncomment test code in this file")
    print("3. Test with small amounts first")


if __name__ == "__main__":
    asyncio.run(test_trading_tools())
