"""Test script for Neo N3 block tools

Tests block-related tools.
This includes both tool-based and provider-based methods.

Usage:
    # Method 1: Run directly (from project root)
    python tests/crypto/neo3/test_block_tools.py
    
    # Method 2: Run with pytest
    pytest tests/crypto/neo3/test_block_tools.py
    
    # Method 3: Run a specific test with pytest
    pytest tests/crypto/neo3/test_block_tools.py::test_block_count -v
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
    GetBlockCountTool,
    GetBestBlockHashTool,
    GetBlockByHashTool,
    GetBlockByHeightTool,
    GetBlockHashTool,
    GetBlockHeaderTool,
)


# Test configuration
NETWORK = "mainnet"  # or "testnet"


@pytest.mark.asyncio
async def test_block_count():
    """Test GetBlockCountTool"""
    print("=" * 70)
    print("Testing GetBlockCountTool")
    print("=" * 70)
    print(f"Network: {NETWORK}")
    
    tool = GetBlockCountTool()
    result = await tool.execute(NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: {result.output}")
    
    provider = Neo3Provider(network=NETWORK)
    try:
        count = await provider.get_block_count()
        print(f"   Provider result: {count}")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_best_block_hash():
    """Test GetBestBlockHashTool"""
    print("\n" + "=" * 70)
    print("Testing GetBestBlockHashTool")
    print("=" * 70)
    
    tool = GetBestBlockHashTool()
    result = await tool.execute(NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: {result.output[:80]}...")
    
    provider = Neo3Provider(network=NETWORK)
    try:
        hash_value = await provider.get_best_block_hash()
        print(f"   Provider result: {hash_value[:50]}...")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_block_by_height():
    """Test GetBlockByHeightTool"""
    print("\n" + "=" * 70)
    print("Testing GetBlockByHeightTool")
    print("=" * 70)
    
    provider = Neo3Provider(network=NETWORK)
    try:
        block_count = await provider.get_block_count()
        if block_count > 0:
            test_height = block_count - 1
            tool = GetBlockByHeightTool()
            result = await tool.execute(test_height, 0, NETWORK)
            if result.error:
                print(f"   ❌ Error: {result.error}")
            else:
                print(f"   ✅ Success: Block retrieved for height {test_height}")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_block_by_hash():
    """Test GetBlockByHashTool"""
    print("\n" + "=" * 70)
    print("Testing GetBlockByHashTool")
    print("=" * 70)
    
    provider = Neo3Provider(network=NETWORK)
    try:
        block_hash = await provider.get_best_block_hash()
        tool = GetBlockByHashTool()
        result = await tool.execute(block_hash, 0, NETWORK)
        if result.error:
            print(f"   ❌ Error: {result.error}")
        else:
            print(f"   ✅ Success: Block retrieved by hash")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_block_hash():
    """Test GetBlockHashTool"""
    print("\n" + "=" * 70)
    print("Testing GetBlockHashTool")
    print("=" * 70)
    
    provider = Neo3Provider(network=NETWORK)
    try:
        block_count = await provider.get_block_count()
        if block_count > 0:
            test_index = block_count - 1
            tool = GetBlockHashTool()
            result = await tool.execute(test_index, NETWORK)
            if result.error:
                print(f"   ❌ Error: {result.error}")
            else:
                print(f"   ✅ Success: {result.output[:80]}...")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_block_header():
    """Test GetBlockHeaderTool"""
    print("\n" + "=" * 70)
    print("Testing GetBlockHeaderTool")
    print("=" * 70)
    
    provider = Neo3Provider(network=NETWORK)
    try:
        block_count = await provider.get_block_count()
        if block_count > 0:
            test_height = str(block_count - 1)
            tool = GetBlockHeaderTool()
            result = await tool.execute(test_height, 0, NETWORK)
            if result.error:
                print(f"   ❌ Error: {result.error}")
            else:
                print(f"   ✅ Success: Block header retrieved")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


async def run_all_tests():
    """Run all block tool tests"""
    print("\n" + "=" * 70)
    print(f"Neo N3 Block Tools Test Suite")
    print(f"Network: {NETWORK}")
    print("=" * 70)
    
    try:
        await test_block_count()
        await test_best_block_hash()
        await test_block_by_height()
        await test_block_by_hash()
        await test_block_hash()
        await test_block_header()
        
        print("\n" + "=" * 70)
        print("✅ All block tool tests completed!")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(run_all_tests())

