"""Test script for Neo N3 transaction tools

Tests transaction-related tools.
This includes both tool-based and provider-based methods.

Usage:
    # Method 1: Run directly (from project root)
    python tests/crypto/neo3/test_transaction_tools.py
    
    # Method 2: Run with pytest
    pytest tests/crypto/neo3/test_transaction_tools.py
    
    # Method 3: Run a specific test with pytest
    pytest tests/crypto/neo3/test_transaction_tools.py::test_raw_mempool -v
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
    GetRawTransactionTool,
    GetRawMempoolTool,
    GetTransactionHeightTool,
    GetApplicationLogTool,
)


# Test configuration
NETWORK = "mainnet"  # or "testnet"


@pytest.mark.asyncio
async def test_raw_mempool():
    """Test GetRawMempoolTool"""
    print("=" * 70)
    print("Testing GetRawMempoolTool")
    print("=" * 70)
    print(f"Network: {NETWORK}")
    
    tool = GetRawMempoolTool()
    result = await tool.execute(0, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    provider = Neo3Provider(network=NETWORK)
    try:
        mempool = await provider.get_raw_mempool()
        print(f"   Provider result: {len(mempool) if isinstance(mempool, list) else 'N/A'} transactions")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_raw_transaction():
    """Test GetRawTransactionTool"""
    print("\n" + "=" * 70)
    print("Testing GetRawTransactionTool")
    print("=" * 70)
    
    provider = Neo3Provider(network=NETWORK)
    try:
        # Get a transaction from latest block
        block_count = await provider.get_block_count()
        if block_count > 0:
            block = await provider.get_block(str(block_count - 1))
            if isinstance(block, dict) and 'tx' in block and len(block['tx']) > 0:
                tx_hash = block['tx'][0] if isinstance(block['tx'][0], str) else str(block['tx'][0])
                tool = GetRawTransactionTool()
                result = await tool.execute(tx_hash, 0, NETWORK)
                if result.error:
                    print(f"   ❌ Error: {result.error}")
                else:
                    print(f"   ✅ Success: Transaction retrieved")
            else:
                print(f"   ⚠️  No transactions in latest block")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_transaction_height():
    """Test GetTransactionHeightTool"""
    print("\n" + "=" * 70)
    print("Testing GetTransactionHeightTool")
    print("=" * 70)
    
    provider = Neo3Provider(network=NETWORK)
    try:
        # Get a transaction from latest block
        block_count = await provider.get_block_count()
        if block_count > 0:
            block = await provider.get_block(str(block_count - 1))
            if isinstance(block, dict) and 'tx' in block and len(block['tx']) > 0:
                tx_hash = block['tx'][0] if isinstance(block['tx'][0], str) else str(block['tx'][0])
                tool = GetTransactionHeightTool()
                result = await tool.execute(tx_hash, NETWORK)
                if result.error:
                    print(f"   ❌ Error: {result.error}")
                else:
                    print(f"   ✅ Success: {result.output}")
            else:
                print(f"   ⚠️  No transactions in latest block")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_application_log():
    """Test GetApplicationLogTool"""
    print("\n" + "=" * 70)
    print("Testing GetApplicationLogTool")
    print("=" * 70)
    
    provider = Neo3Provider(network=NETWORK)
    try:
        # Get a transaction from latest block
        block_count = await provider.get_block_count()
        if block_count > 0:
            block = await provider.get_block(str(block_count - 1))
            if isinstance(block, dict) and 'tx' in block and len(block['tx']) > 0:
                tx_hash = block['tx'][0] if isinstance(block['tx'][0], str) else str(block['tx'][0])
                tool = GetApplicationLogTool()
                result = await tool.execute(tx_hash, NETWORK)
                if result.error:
                    print(f"   ⚠️  Application log not available: {result.error[:50]}...")
                else:
                    print(f"   ✅ Success: Application log retrieved")
            else:
                print(f"   ⚠️  No transactions in latest block")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


async def run_all_tests():
    """Run all transaction tool tests"""
    print("\n" + "=" * 70)
    print(f"Neo N3 Transaction Tools Test Suite")
    print(f"Network: {NETWORK}")
    print("=" * 70)
    
    try:
        await test_raw_mempool()
        await test_raw_transaction()
        await test_transaction_height()
        await test_application_log()
        
        print("\n" + "=" * 70)
        print("✅ All transaction tool tests completed!")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(run_all_tests())

