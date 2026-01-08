"""Test account management tools (requires authentication)"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from spoon_toolkits.deribit.env import DeribitConfig
from spoon_toolkits.deribit.account import GetAccountSummaryTool, GetPositionsTool


async def test_account_tools():
    """Test account management tools"""
    print("=" * 60)
    print("Testing Account Management Tools")
    print("=" * 60)
    
    # Check credentials
    if not DeribitConfig.validate_credentials():
        print("❌ Error: API credentials not configured!")
        print("   Account tools require authentication.")
        return
    
    tools_tested = 0
    tools_passed = 0
    
    # Test 1: GetAccountSummaryTool
    print("\n[Test 1] GetAccountSummaryTool")
    tools_tested += 1
    try:
        tool = GetAccountSummaryTool()
        result = await tool.execute(currency="BTC")
        if result.error:
            print(f"❌ Failed: {result.error}")
        else:
            print("✅ Success! Account summary retrieved")
            print(f"   Balance: {result.output.get('balance', 'N/A')} BTC")
            print(f"   Equity: {result.output.get('equity', 'N/A')} BTC")
            print(f"   Available: {result.output.get('available_funds', 'N/A')} BTC")
            tools_passed += 1
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # Test 2: GetPositionsTool
    print("\n[Test 2] GetPositionsTool")
    tools_tested += 1
    try:
        tool = GetPositionsTool()
        result = await tool.execute(currency="BTC")
        if result.error:
            print(f"❌ Failed: {result.error}")
        else:
            positions = result.output if isinstance(result.output, list) else []
            print(f"✅ Success! Found {len(positions)} positions")
            if positions:
                pos = positions[0]
                print(f"   Example position: {pos.get('instrument_name', 'N/A')}")
                print(f"   Size: {pos.get('size', 'N/A')}")
            tools_passed += 1
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print(f"Account Tools Test Summary: {tools_passed}/{tools_tested} passed")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_account_tools())

