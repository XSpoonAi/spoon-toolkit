"""Test public API (no authentication required)"""

import asyncio
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from spoon_toolkits.deribit.jsonrpc_client import DeribitJsonRpcClient


async def test_public_api():
    """Test public API calls"""
    print("=" * 60)
    print("Testing Deribit Public API (No Authentication Required)")
    print("=" * 60)
    
    async with DeribitJsonRpcClient() as client:
        # Test 1: Get instruments
        print("\n[Test 1] Getting BTC instruments...")
        try:
            result = await client.call(
                "public/get_instruments",
                {"currency": "BTC", "kind": "future"}
            )
            print(f"✅ Success! Found {len(result)} BTC futures instruments")
            if result:
                print(f"   Example: {result[0].get('instrument_name', 'N/A')}")
        except Exception as e:
            print(f"❌ Failed: {e}")
        
        # Test 2: Get order book
        print("\n[Test 2] Getting order book for BTC-PERPETUAL...")
        try:
            result = await client.call(
                "public/get_order_book",
                {"instrument_name": "BTC-PERPETUAL", "depth": 5}
            )
            print(f"✅ Success! Order book retrieved")
            if result.get("bids"):
                print(f"   Best bid: {result['bids'][0]}")
            if result.get("asks"):
                print(f"   Best ask: {result['asks'][0]}")
        except Exception as e:
            print(f"❌ Failed: {e}")
        
        # Test 3: Get ticker
        print("\n[Test 3] Getting ticker for BTC-PERPETUAL...")
        try:
            result = await client.call(
                "public/ticker",
                {"instrument_name": "BTC-PERPETUAL"}
            )
            print(f"✅ Success! Ticker retrieved")
            print(f"   Last price: {result.get('last_price', 'N/A')}")
            print(f"   Mark price: {result.get('mark_price', 'N/A')}")
        except Exception as e:
            print(f"❌ Failed: {e}")
        
        # Test 4: Get index price
        print("\n[Test 4] Getting BTC index price...")
        try:
            result = await client.call(
                "public/get_index_price",
                {"index_name": "btc_usd"}
            )
            print(f"✅ Success! Index price retrieved")
            print(f"   Index price: {result.get('index_price', 'N/A')}")
        except Exception as e:
            print(f"❌ Failed: {e}")
    
    print("\n" + "=" * 60)
    print("Public API Test Complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_public_api())

