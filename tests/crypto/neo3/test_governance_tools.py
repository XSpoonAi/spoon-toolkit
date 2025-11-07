"""Test script for Neo N3 governance tools

Tests governance-related tools including committee and validators.
This includes both tool-based and provider-based methods.

Note: GetNativeContractsTool is now in contract_tools (see test_contract_tools.py)

Usage:
    # Method 1: Run directly (from project root)
    python tests/crypto/neo3/test_governance_tools.py
    
    # Method 2: Run with pytest
    pytest tests/crypto/neo3/test_governance_tools.py
    
    # Method 3: Run a specific test with pytest
    pytest tests/crypto/neo3/test_governance_tools.py::test_committee -v
"""

import asyncio
import json
import sys
from pathlib import Path
import pytest

# Add project root to Python path for imports
project_root = Path(__file__).parent.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from spoon_toolkits.crypto.neo3 import (
    Neo3Provider,
    GetCommitteeTool,
    GetNextBlockValidatorsTool,
)


# Test configuration
NETWORK = "mainnet"  # or "testnet"


def format_data(data):
    """Format data for display"""
    if isinstance(data, dict):
        return json.dumps(data, indent=2)
    elif isinstance(data, list):
        return json.dumps(data, indent=2)
    elif hasattr(data, '__dict__'):
        return json.dumps(data.__dict__, indent=2, default=str)
    else:
        return str(data)


@pytest.mark.asyncio
async def test_committee():
    """Test committee information"""
    print("=" * 70)
    print("Testing Committee Information")
    print("=" * 70)
    print(f"Network: {NETWORK}")
    
    # Test using GetCommitteeTool
    print("\n1. Testing GetCommitteeTool...")
    tool = GetCommitteeTool()
    result = await tool.execute(NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    # Test using provider directly for detailed output
    print("\n2. Testing Neo3Provider.get_committee() directly...")
    provider = Neo3Provider(network=NETWORK)
    try:
        committee = await provider.get_committee()
        print(f"   ✅ Success: Committee retrieved")
        
        if isinstance(committee, list):
            print(f"\n   📊 Committee Summary:")
            print(f"      Total members: {len(committee)}")
            
            if committee:
                print(f"\n   👥 Committee Members:")
                for i, member in enumerate(committee[:5], 1):  # Show first 5
                    print(f"      {i}. {member[:50]}...")
                if len(committee) > 5:
                    print(f"      ... ({len(committee) - 5} more members)")
        else:
            print(f"   Response type: {type(committee)}")
            print(f"   Response: {format_data(committee)[:200]}...")
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_next_block_validators():
    """Test next block validators information"""
    print("\n" + "=" * 70)
    print("Testing Next Block Validators")
    print("=" * 70)
    print(f"Network: {NETWORK}")
    
    # Test using GetNextBlockValidatorsTool
    print("\n1. Testing GetNextBlockValidatorsTool...")
    tool = GetNextBlockValidatorsTool()
    result = await tool.execute(NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    # Test using provider directly for detailed output
    print("\n2. Testing Neo3Provider.get_next_block_validators() directly...")
    provider = Neo3Provider(network=NETWORK)
    try:
        validators = await provider.get_next_block_validators()
        print(f"   ✅ Success: Next block validators retrieved")
        
        if isinstance(validators, list):
            print(f"\n   📊 Validators Summary:")
            print(f"      Total validators: {len(validators)}")
            
            if validators:
                print(f"\n   ✅ Next Block Validators:")
                for i, validator in enumerate(validators[:5], 1):  # Show first 5
                    if isinstance(validator, dict):
                        public_key = validator.get('publickey', 'N/A')
                        votes = validator.get('votes', 'N/A')
                        print(f"\n      Validator {i}:")
                        print(f"         Public Key: {public_key[:50]}...")
                        print(f"         Votes: {votes}")
                if len(validators) > 5:
                    print(f"\n      ... ({len(validators) - 5} more validators)")
        else:
            print(f"   Response type: {type(validators)}")
            print(f"   Response: {format_data(validators)[:200]}...")
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_complete_governance_info():
    """Test complete governance information summary"""
    print("\n" + "=" * 70)
    print("Complete Governance Information Summary")
    print("=" * 70)
    print(f"Network: {NETWORK}")
    
    provider = Neo3Provider(network=NETWORK)
    
    try:
        # Get committee
        print("\n👥 Committee:")
        committee = await provider.get_committee()
        if isinstance(committee, list):
            print(f"   Members: {len(committee)}")
        else:
            print(f"   Status: Retrieved")
        
        # Get next block validators
        print("\n✅ Next Block Validators:")
        validators = await provider.get_next_block_validators()
        if isinstance(validators, list):
            print(f"   Count: {len(validators)} validators")
        else:
            print(f"   Status: Retrieved")
        
        print("\n" + "=" * 70)
        print("✅ Complete governance information retrieved successfully!")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await provider.close()


async def run_all_tests():
    """Run all governance tests"""
    print("\n" + "=" * 70)
    print(f"Neo N3 Governance Test Suite")
    print(f"Network: {NETWORK}")
    print("=" * 70)
    
    try:
        await test_committee()
        await test_next_block_validators()
        await test_complete_governance_info()
        
        print("\n" + "=" * 70)
        print("✅ All governance tests completed!")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(run_all_tests())

