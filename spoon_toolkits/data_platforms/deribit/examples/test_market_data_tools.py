"""Test market data tools"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from spoon_toolkits.deribit.market_data import (
    GetInstrumentsTool,
    GetOrderBookTool,
    GetTickerTool,
    GetLastTradesTool,
    GetIndexPriceTool,
    GetBookSummaryTool
)


async def test_market_data_tools():
    """Test all market data tools"""
    print("=" * 60)
    print("Testing Market Data Tools")
    print("=" * 60)
    
    tools_tested = 0
    tools_passed = 0
    
    # Test 1: GetInstrumentsTool
    print("\n[Test 1] GetInstrumentsTool")
    tools_tested += 1
    try:
        tool = GetInstrumentsTool()
        result = await tool.execute(currency="BTC", kind="future")
        if isinstance(result, dict) and result.get("error"):
            print(f"❌ Failed: {result.get('error')}")
        else:
            output = result.get("output") if isinstance(result, dict) else result
            print(f"✅ Success! Found {len(output)} instruments")
            tools_passed += 1
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # Test 2: GetOrderBookTool
    print("\n[Test 2] GetOrderBookTool")
    tools_tested += 1
    try:
        tool = GetOrderBookTool()
        result = await tool.execute(instrument_name="BTC-PERPETUAL", depth=5)
        if isinstance(result, dict) and result.get("error"):
            print(f"❌ Failed: {result.get('error')}")
        else:
            output = result.get("output") if isinstance(result, dict) else result
            print(f"✅ Success! Order book retrieved")
            if output.get("bids"):
                print(f"   Best bid: {output['bids'][0]}")
            tools_passed += 1
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # Test 3: GetTickerTool
    print("\n[Test 3] GetTickerTool")
    tools_tested += 1
    try:
        tool = GetTickerTool()
        result = await tool.execute(instrument_name="BTC-PERPETUAL")
        if isinstance(result, dict) and result.get("error"):
            print(f"❌ Failed: {result.get('error')}")
        else:
            output = result.get("output") if isinstance(result, dict) else result
            print(f"✅ Success! Ticker retrieved")
            print(f"   Last price: {output.get('last_price', 'N/A')}")
            tools_passed += 1
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # Test 4: GetLastTradesTool
    print("\n[Test 4] GetLastTradesTool")
    tools_tested += 1
    try:
        tool = GetLastTradesTool()
        result = await tool.execute(instrument_name="BTC-PERPETUAL", count=5)
        if isinstance(result, dict) and result.get("error"):
            print(f"❌ Failed: {result.get('error')}")
        else:
            output = result.get("output") if isinstance(result, dict) else result
            trades = output.get("trades", []) if isinstance(output, dict) else []
            print(f"✅ Success! Retrieved {len(trades)} trades")
            tools_passed += 1
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # Test 5: GetIndexPriceTool
    print("\n[Test 5] GetIndexPriceTool")
    tools_tested += 1
    try:
        tool = GetIndexPriceTool()
        result = await tool.execute(index_name="btc_usd")
        if isinstance(result, dict) and result.get("error"):
            print(f"❌ Failed: {result.get('error')}")
        else:
            output = result.get("output") if isinstance(result, dict) else result
            print(f"✅ Success! Index price: {output.get('index_price', 'N/A')}")
            tools_passed += 1
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # Test 6: GetBookSummaryTool
    print("\n[Test 6] GetBookSummaryTool")
    tools_tested += 1
    try:
        tool = GetBookSummaryTool()
        result = await tool.execute(currency="BTC", kind="future")
        if isinstance(result, dict) and result.get("error"):
            print(f"❌ Failed: {result.get('error')}")
        else:
            output = result.get("output") if isinstance(result, dict) else result
            print(f"✅ Success! Retrieved {len(output)} book summaries")
            tools_passed += 1
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print(f"Market Data Tools Test Summary: {tools_passed}/{tools_tested} passed")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_market_data_tools())

