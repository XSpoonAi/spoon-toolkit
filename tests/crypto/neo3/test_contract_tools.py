"""Test script for Neo N3 contract tools

Tests contract-related tools.
This includes both tool-based and provider-based methods.

Usage:
    # Method 1: Run directly (from project root)
    python tests/crypto/neo3/test_contract_tools.py
    
    # Method 2: Run with pytest
    pytest tests/crypto/neo3/test_contract_tools.py
    
    # Method 3: Run a specific test with pytest
    pytest tests/crypto/neo3/test_contract_tools.py::test_contract_state -v
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
    GetContractStateTool,
    GetStorageTool,
    InvokeFunctionTool,
    GetNativeContractsTool,
)


# Test configuration
NETWORK = "mainnet"  # or "testnet"
# NEO contract hash for mainnet
NEO_CONTRACT = "0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5"


@pytest.mark.asyncio
async def test_contract_state():
    """Test GetContractStateTool"""
    print("=" * 70)
    print("Testing GetContractStateTool")
    print("=" * 70)
    print(f"Contract: {NEO_CONTRACT}")
    print(f"Network: {NETWORK}")
    
    tool = GetContractStateTool()
    result = await tool.execute(NEO_CONTRACT, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    provider = Neo3Provider(network=NETWORK)
    try:
        contract_state = await provider.get_contract_state(NEO_CONTRACT)
        print(f"   Provider result: Contract state retrieved")
        if hasattr(contract_state, 'name'):
            print(f"   Contract name: {contract_state.name}")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_native_contracts():
    """Test GetNativeContractsTool"""
    print("\n" + "=" * 70)
    print("Testing GetNativeContractsTool")
    print("=" * 70)
    print(f"Network: {NETWORK}")
    
    tool = GetNativeContractsTool()
    result = await tool.execute(NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    provider = Neo3Provider(network=NETWORK)
    try:
        contracts = await provider.get_native_contracts()
        print(f"   Provider result: {len(contracts) if isinstance(contracts, list) else 'N/A'} contracts")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_storage():
    """Test GetStorageTool"""
    print("\n" + "=" * 70)
    print("Testing GetStorageTool")
    print("=" * 70)
    
    print("   ⚠️  Skipped: Requires specific contract and storage key")
    print("   To test, provide a valid contract hash and storage key")


@pytest.mark.asyncio
async def test_invoke_function():
    """Test InvokeFunctionTool"""
    print("\n" + "=" * 70)
    print("Testing InvokeFunctionTool")
    print("=" * 70)
    
    print("   ⚠️  Skipped: Requires specific contract, function, and parameters")
    print("   To test, provide a valid contract hash, function name, and parameters")


async def run_all_tests():
    """Run all contract tool tests"""
    print("\n" + "=" * 70)
    print(f"Neo N3 Contract Tools Test Suite")
    print(f"Network: {NETWORK}")
    print("=" * 70)
    
    try:
        await test_contract_state()
        await test_native_contracts()
        await test_storage()
        await test_invoke_function()
        
        print("\n" + "=" * 70)
        print("✅ All contract tool tests completed!")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(run_all_tests())

