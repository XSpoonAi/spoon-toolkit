"""Simple test script for Neo N3 get_nep17_balances tool

Usage:
    # Method 1: Run directly (from project root)
    python tests/crypto/neo3/test_neo3_get_nep17_balances.py
    
    # Method 2: Run with pytest
    pytest tests/crypto/neo3/test_neo3_get_nep17_balances.py
    
    # Method 3: Run from tests directory
    cd tests/crypto/neo3 && python test_neo3_get_nep17_balances.py
"""

import asyncio
import json
import sys
from pathlib import Path

# Add project root to Python path for imports
project_root = Path(__file__).parent.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from spoon_toolkits.crypto.neo3 import GetNep17BalancesTool, Neo3Provider


async def test_get_nep17_balances():
    """Test the GetNep17BalancesTool"""
    # Test address - you can change this to any Neo address
    test_address = "NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp"  # Example Neo address
    network = "mainnet"  # or "testnet"
    
    print(f"Testing GetNep17BalancesTool for Neo N3")
    print(f"Network: {network}")
    print(f"Address: {test_address}")
    print("=" * 60)
    
    try:
        # Test using the tool
        print("\n1. Testing GetNep17BalancesTool...")
        tool = GetNep17BalancesTool()
        result = await tool.execute(test_address, network)
        
        if result.error:
            print(f"   ❌ Error: {result.error}")
        else:
            print(f"   ✅ Success!")
            print(f"   Output: {result.output}")
        
        # Test using the provider directly for more detailed output
        print("\n2. Testing Neo3Provider.get_nep17_balances() directly...")
        provider = Neo3Provider(network=network)
        balances_response = await provider.get_nep17_balances(test_address)
        
        print(f"   ✅ Success!")
        print(f"\n   Full response type: {type(balances_response)}")
        
        # Handle balances response (Nep17BalancesResponse object)
        if hasattr(balances_response, 'balances'):
            balances_list = balances_response.balances
            print(f"   Balances type: {type(balances_list)}")
            print(f"   Balances count: {len(balances_list)}")
            
            # If there are balances, show them in detail
            if balances_list:
                print(f"\n   📊 Token Balances ({len(balances_list)} tokens):")
                for i, balance in enumerate(balances_list, 1):
                    print(f"\n   {i}. Token Balance:")
                    # Try to show balance details if available
                    if hasattr(balance, '__dict__'):
                        balance_dict = balance.__dict__
                        for key, value in balance_dict.items():
                            print(f"      {key}: {value}")
                    else:
                        print(f"      {balance}")
            else:
                print(f"\n   ⚠️  No NEP-17 token balances found for this address.")
                print(f"      This is normal if the address hasn't received any NEP-17 tokens.")
        else:
            print(f"   Response structure: {type(balances_response)}")
            print(f"   Response: {balances_response}")
        
        # Close the connection
        await provider.close()
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_get_nep17_balances())

