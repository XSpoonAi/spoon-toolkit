"""Test script for Neo N3 NEP tools

Tests NEP-17 and NEP-11 related tools.
This includes both tool-based and provider-based methods.

Usage:
    # Method 1: Run directly (from project root)
    python tests/crypto/neo3/test_nep_tools.py
    
    # Method 2: Run with pytest
    pytest tests/crypto/neo3/test_nep_tools.py
    
    # Method 3: Run a specific test with pytest
    pytest tests/crypto/neo3/test_nep_tools.py::test_nep17_balances -v
"""

import asyncio
import sys
from pathlib import Path
import pytest

# Add project root to Python path for imports
project_root = Path(__file__).parent.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from spoon_toolkits.crypto.neo3 import (
    Neo3Provider,
    GetNep17BalancesTool,
    GetNep17TransfersTool,
    GetNep11BalancesTool,
    GetNep11PropertiesTool,
    GetNep11TransfersTool,
)


# Test configuration
TEST_ADDRESS = "NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp"  # Change to your test address
NETWORK = "mainnet"  # or "testnet"


@pytest.mark.asyncio
async def test_nep17_balances():
    """Test GetNep17BalancesTool"""
    print("=" * 70)
    print("Testing GetNep17BalancesTool")
    print("=" * 70)
    print(f"Address: {TEST_ADDRESS}")
    print(f"Network: {NETWORK}")
    
    # Test using tool
    print("\n1. Testing GetNep17BalancesTool...")
    tool = GetNep17BalancesTool()
    result = await tool.execute(TEST_ADDRESS, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    # Test using provider
    print("\n2. Testing Neo3Provider.get_nep17_balances()...")
    provider = Neo3Provider(network=NETWORK)
    try:
        balances = await provider.get_nep17_balances(TEST_ADDRESS)
        print(f"   ✅ Success: Balances retrieved")
        if hasattr(balances, 'balances'):
            print(f"   Token count: {len(balances.balances)}")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_nep17_transfers():
    """Test GetNep17TransfersTool"""
    print("\n" + "=" * 70)
    print("Testing GetNep17TransfersTool")
    print("=" * 70)
    print(f"Address: {TEST_ADDRESS}")
    print(f"Network: {NETWORK}")
    
    # Test using tool
    print("\n1. Testing GetNep17TransfersTool...")
    tool = GetNep17TransfersTool()
    result = await tool.execute(TEST_ADDRESS, None, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    # Test using provider
    print("\n2. Testing Neo3Provider.get_nep17_transfers()...")
    provider = Neo3Provider(network=NETWORK)
    try:
        transfers = await provider.get_nep17_transfers(TEST_ADDRESS)
        print(f"   ✅ Success: Transfers retrieved")
        if isinstance(transfers, dict):
            sent = len(transfers.get('sent', [])) if isinstance(transfers.get('sent'), list) else 0
            received = len(transfers.get('received', [])) if isinstance(transfers.get('received'), list) else 0
            print(f"   Sent: {sent}, Received: {received}")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_nep11_balances():
    """Test GetNep11BalancesTool"""
    print("\n" + "=" * 70)
    print("Testing GetNep11BalancesTool")
    print("=" * 70)
    print(f"Address: {TEST_ADDRESS}")
    print(f"Network: {NETWORK}")
    
    # Test using tool
    print("\n1. Testing GetNep11BalancesTool...")
    tool = GetNep11BalancesTool()
    result = await tool.execute(TEST_ADDRESS, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    # Test using provider
    print("\n2. Testing Neo3Provider.get_nep11_balances()...")
    provider = Neo3Provider(network=NETWORK)
    try:
        balances = await provider.get_nep11_balances(TEST_ADDRESS)
        print(f"   ✅ Success: Balances retrieved")
        if isinstance(balances, dict) and 'balance' in balances:
            nft_count = len(balances['balance']) if isinstance(balances['balance'], list) else 0
            print(f"   NFT count: {nft_count}")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_nep11_transfers():
    """Test GetNep11TransfersTool"""
    print("\n" + "=" * 70)
    print("Testing GetNep11TransfersTool")
    print("=" * 70)
    print(f"Address: {TEST_ADDRESS}")
    print(f"Network: {NETWORK}")
    
    # Test using tool
    print("\n1. Testing GetNep11TransfersTool...")
    tool = GetNep11TransfersTool()
    result = await tool.execute(TEST_ADDRESS, None, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    # Test using provider
    print("\n2. Testing Neo3Provider.get_nep11_transfers()...")
    provider = Neo3Provider(network=NETWORK)
    try:
        transfers = await provider.get_nep11_transfers(TEST_ADDRESS)
        print(f"   ✅ Success: Transfers retrieved")
        if isinstance(transfers, dict):
            sent = len(transfers.get('sent', [])) if isinstance(transfers.get('sent'), list) else 0
            received = len(transfers.get('received', [])) if isinstance(transfers.get('received'), list) else 0
            print(f"   Sent: {sent}, Received: {received}")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_nep11_properties():
    """Test GetNep11PropertiesTool"""
    print("\n" + "=" * 70)
    print("Testing GetNep11PropertiesTool")
    print("=" * 70)
    print(f"Network: {NETWORK}")
    
    # Note: This requires a valid contract_hash and token_id
    print("\n⚠️  Skipped: Requires specific contract_hash and token_id")
    print("   To test, provide a valid NEP-11 contract hash and token ID")


async def run_all_tests():
    """Run all NEP tool tests"""
    print("\n" + "=" * 70)
    print(f"Neo N3 NEP Tools Test Suite")
    print(f"Network: {NETWORK}")
    print(f"Test Address: {TEST_ADDRESS}")
    print("=" * 70)
    
    try:
        await test_nep17_balances()
        await test_nep17_transfers()
        await test_nep11_balances()
        await test_nep11_transfers()
        await test_nep11_properties()
        
        print("\n" + "=" * 70)
        print("✅ All NEP tool tests completed!")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(run_all_tests())

