"""Test script for Neo N3 utility tools

Tests utility-related tools.
This includes both tool-based and provider-based methods.

Usage:
    # Method 1: Run directly (from project root)
    python tests/crypto/neo3/test_utility_tools.py
    
    # Method 2: Run with pytest
    pytest tests/crypto/neo3/test_utility_tools.py
    
    # Method 3: Run a specific test with pytest
    pytest tests/crypto/neo3/test_utility_tools.py::test_validate_address -v
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
    ValidateAddressTool,
)


# Test configuration
TEST_ADDRESS = "NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp"  # Valid address
INVALID_ADDRESS = "invalid_address_123"  # Invalid address
NETWORK = "mainnet"  # or "testnet"


@pytest.mark.asyncio
async def test_validate_address():
    """Test ValidateAddressTool"""
    print("=" * 70)
    print("Testing ValidateAddressTool")
    print("=" * 70)
    print(f"Network: {NETWORK}")
    
    # Test valid address
    print("\n1. Testing with valid address...")
    tool = ValidateAddressTool()
    result = await tool.execute(TEST_ADDRESS, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: {result.output}")
    
    # Test invalid address
    print("\n2. Testing with invalid address...")
    result = await tool.execute(INVALID_ADDRESS, NETWORK)
    if result.error:
        print(f"   ✅ Success: Correctly identified as invalid")
    else:
        print(f"   Result: {result.output}")
    
    # Test using provider
    print("\n3. Testing Neo3Provider.validate_address()...")
    provider = Neo3Provider(network=NETWORK)
    try:
        is_valid = provider.validate_address(TEST_ADDRESS)
        print(f"   Valid address result: {is_valid}")
        is_invalid = provider.validate_address(INVALID_ADDRESS)
        print(f"   Invalid address result: {is_invalid}")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


async def run_all_tests():
    """Run all utility tool tests"""
    print("\n" + "=" * 70)
    print(f"Neo N3 Utility Tools Test Suite")
    print(f"Network: {NETWORK}")
    print("=" * 70)
    
    try:
        await test_validate_address()
        
        print("\n" + "=" * 70)
        print("✅ All utility tool tests completed!")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(run_all_tests())

