"""Comprehensive test script for all Neo N3 blockchain methods

Tests all tools and provider methods that are officially available in Neo N3 RPC API.
Reference: https://developers.neo.org/docs/n3/reference/rpc/api

Usage:
    # Method 1: Run directly (from project root)
    python tests/crypto/neo3/test_all_neo3_methods.py
    
    # Method 2: Run with pytest (runs all tests individually)
    pytest tests/crypto/neo3/test_all_neo3_methods.py
    
    # Method 3: Run a specific test with pytest
    pytest tests/crypto/neo3/test_all_neo3_methods.py::test_provider_methods -v
"""

import asyncio
import sys
from pathlib import Path
import pytest

# Add project root to Python path for imports
project_root = Path(__file__).parent.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from spoon_toolkits.crypto.neo3 import Neo3Provider
from spoon_toolkits.crypto.neo3 import (
    # NEP tools
    GetNep17BalancesTool,
    GetNep17TransfersTool,
    GetNep11BalancesTool,
    GetNep11PropertiesTool,
    GetNep11TransfersTool,
    # Block tools
    GetBlockCountTool,
    GetBestBlockHashTool,
    GetBlockByHashTool,
    GetBlockByHeightTool,
    GetBlockHashTool,
    GetBlockHeaderTool,
    # Transaction tools
    GetRawTransactionTool,
    GetRawMempoolTool,
    GetTransactionHeightTool,
    GetApplicationLogTool,
    # Contract tools
    GetContractStateTool,
    GetStorageTool,
    InvokeFunctionTool,
    GetNativeContractsTool,
    # Governance tools
    GetCommitteeTool,
    GetNextBlockValidatorsTool,
    # Utility tools
    ValidateAddressTool,
)


# Test configuration
TEST_ADDRESS = "NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp"  # Change to your test address
NETWORK = "mainnet"  # or "testnet"


@pytest.mark.asyncio
async def test_provider_methods():
    """Test Neo3Provider methods"""
    print("=" * 70)
    print("Testing Neo3Provider Methods")
    print("=" * 70)
    
    provider = Neo3Provider(network=NETWORK)
    
    try:
        # Test get_block_count
        print("\n1. Testing get_block_count...")
        block_count = await provider.get_block_count()
        print(f"   ✅ Success: Block count = {block_count}")
        
        # Test get_best_block_hash
        print("\n2. Testing get_best_block_hash...")
        best_hash = await provider.get_best_block_hash()
        print(f"   ✅ Success: Best block hash = {best_hash[:20]}...")
        
        # Test get_block_by_height (get latest block)
        if block_count > 0:
            print("\n3. Testing get_block_by_height (latest block)...")
            block = await provider.get_block(str(block_count - 1))
            print(f"   ✅ Success: Block retrieved")
            if isinstance(block, dict) and 'hash' in block:
                print(f"   Block hash: {block.get('hash', 'N/A')[:20]}...")
        
        # Test get_block_hash
        if block_count > 0:
            print("\n4. Testing get_block_hash...")
            block_hash = await provider.get_block_hash(block_count - 1)
            print(f"   ✅ Success: Block hash = {block_hash[:20]}...")
        
        # Test get_committee
        print("\n5. Testing get_committee...")
        committee = await provider.get_committee()
        print(f"   ✅ Success: Committee members = {len(committee) if isinstance(committee, list) else 'N/A'}")
        if isinstance(committee, list) and committee:
            print(f"   First committee member: {committee[0][:50]}...")
        
        # Test get_native_contracts
        print("\n6. Testing get_native_contracts...")
        contracts = await provider.get_native_contracts()
        print(f"   ✅ Success: Native contracts = {len(contracts) if isinstance(contracts, list) else 'N/A'}")
        if isinstance(contracts, list) and contracts:
            first_contract = contracts[0]
            if isinstance(first_contract, dict):
                print(f"   First contract: ID={first_contract.get('id', 'N/A')}, Hash={first_contract.get('hash', 'N/A')[:30]}...")
        
        # Test get_next_block_validators
        print("\n6b. Testing get_next_block_validators...")
        validators = await provider.get_next_block_validators()
        print(f"   ✅ Success: Next block validators = {len(validators) if isinstance(validators, list) else 'N/A'}")
        if isinstance(validators, list) and validators:
            first_validator = validators[0]
            if isinstance(first_validator, dict):
                print(f"   First validator public key: {first_validator.get('publickey', 'N/A')[:50]}...")
        
        # Test get_nep17_balances
        print("\n7. Testing get_nep17_balances...")
        balances = await provider.get_nep17_balances(TEST_ADDRESS)
        if hasattr(balances, 'balances'):
            balance_count = len(balances.balances)
            print(f"   ✅ Success: NEP-17 balances found = {balance_count}")
        else:
            print(f"   ✅ Success: Response received")
        
        # Test get_nep11_balances
        print("\n8. Testing get_nep11_balances...")
        nep11_balances = await provider.get_nep11_balances(TEST_ADDRESS)
        print(f"   ✅ Success: NEP-11 balances retrieved")
        
        # Test get_connection_count
        print("\n9. Testing get_connection_count...")
        conn_count = await provider.get_connection_count()
        print(f"   ✅ Success: Connection count = {conn_count}")
        
        # Test get_version
        print("\n10. Testing get_version...")
        version = await provider.get_version()
        print(f"   ✅ Success: Version info retrieved")
        if isinstance(version, dict):
            print(f"   Version: {version.get('useragent', 'N/A')}")
        
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_nep_tools():
    """Test NEP-related tools"""
    print("\n" + "=" * 70)
    print("Testing NEP Tools")
    print("=" * 70)
    
    # Test GetNep17BalancesTool
    print("\n1. Testing GetNep17BalancesTool...")
    tool = GetNep17BalancesTool()
    result = await tool.execute(TEST_ADDRESS, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: {result.output[:100]}...")
    
    # Test GetNep17TransfersTool
    print("\n2. Testing GetNep17TransfersTool...")
    tool = GetNep17TransfersTool()
    result = await tool.execute(TEST_ADDRESS, None, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: {result.output[:100]}...")
    
    # Test GetNep11BalancesTool
    print("\n3. Testing GetNep11BalancesTool...")
    tool = GetNep11BalancesTool()
    result = await tool.execute(TEST_ADDRESS, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: {result.output[:100]}...")
    
    # Test GetNep11TransfersTool
    print("\n4. Testing GetNep11TransfersTool...")
    tool = GetNep11TransfersTool()
    result = await tool.execute(TEST_ADDRESS, None, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: {result.output[:100]}...")
    
    # Note: GetNep11PropertiesTool requires contract_hash and token_id
    # Skipping as we don't have test data


@pytest.mark.asyncio
async def test_block_tools():
    """Test block-related tools"""
    print("\n" + "=" * 70)
    print("Testing Block Tools")
    print("=" * 70)
    
    # Test GetBlockCountTool
    print("\n1. Testing GetBlockCountTool...")
    tool = GetBlockCountTool()
    result = await tool.execute(NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: {result.output}")
    
    # Test GetBestBlockHashTool
    print("\n2. Testing GetBestBlockHashTool...")
    tool = GetBestBlockHashTool()
    result = await tool.execute(NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: {result.output[:80]}...")
    
    # Test GetBlockByHeightTool (get latest block)
    print("\n3. Testing GetBlockByHeightTool (latest block)...")
    # Get block count first
    provider = Neo3Provider(network=NETWORK)
    try:
        block_count = await provider.get_block_count()
        if block_count > 0:
            tool = GetBlockByHeightTool()
            result = await tool.execute(block_count - 1, 0, NETWORK)
            if result.error:
                print(f"   ❌ Error: {result.error}")
            else:
                print(f"   ✅ Success: Block retrieved")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    
    # Test GetBlockHashTool
    print("\n4. Testing GetBlockHashTool...")
    provider = Neo3Provider(network=NETWORK)
    try:
        block_count = await provider.get_block_count()
        if block_count > 0:
            tool = GetBlockHashTool()
            result = await tool.execute(block_count - 1, NETWORK)
            if result.error:
                print(f"   ❌ Error: {result.error}")
            else:
                print(f"   ✅ Success: {result.output[:80]}...")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    
    # Test GetBlockHeaderTool
    print("\n5. Testing GetBlockHeaderTool...")
    provider = Neo3Provider(network=NETWORK)
    try:
        block_count = await provider.get_block_count()
        if block_count > 0:
            tool = GetBlockHeaderTool()
            result = await tool.execute(str(block_count - 1), 0, NETWORK)
            if result.error:
                print(f"   ❌ Error: {result.error}")
            else:
                print(f"   ✅ Success: Block header retrieved")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_utility_tools():
    """Test utility tools"""
    print("\n" + "=" * 70)
    print("Testing Utility Tools")
    print("=" * 70)
    
    # Test ValidateAddressTool
    print("\n1. Testing ValidateAddressTool...")
    tool = ValidateAddressTool()
    result = await tool.execute(TEST_ADDRESS, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: {result.output}")


@pytest.mark.asyncio
async def test_transaction_methods():
    """Test transaction-related provider methods"""
    print("\n" + "=" * 70)
    print("Testing Transaction Provider Methods")
    print("=" * 70)
    
    provider = Neo3Provider(network=NETWORK)
    
    try:
        # Get a recent block to find a transaction
        block_count = await provider.get_block_count()
        if block_count > 0:
            print("\n1. Testing get_raw_transaction (from latest block)...")
            block = await provider.get_block(str(block_count - 1))
            if isinstance(block, dict) and 'tx' in block and len(block['tx']) > 0:
                tx_hash = block['tx'][0] if isinstance(block['tx'][0], str) else str(block['tx'][0])
                tx = await provider.get_raw_transaction(tx_hash)
                print(f"   ✅ Success: Transaction retrieved")
            else:
                print(f"   ⚠️  No transactions in latest block")
        
        # Test get_raw_mempool
        print("\n2. Testing get_raw_mempool...")
        mempool = await provider.get_raw_mempool()
        print(f"   ✅ Success: Mempool transactions = {len(mempool) if isinstance(mempool, list) else 'N/A'}")
        
        # Test get_transaction_height
        if block_count > 0:
            print("\n3. Testing get_transaction_height...")
            block = await provider.get_block(str(block_count - 1))
            if isinstance(block, dict) and 'tx' in block and len(block['tx']) > 0:
                tx_hash = block['tx'][0] if isinstance(block['tx'][0], str) else str(block['tx'][0])
                tx_height = await provider.get_transaction_height(tx_hash)
                print(f"   ✅ Success: Transaction height = {tx_height}")
        
        # Test get_application_log
        if block_count > 0:
            print("\n4. Testing get_application_log...")
            block = await provider.get_block(str(block_count - 1))
            if isinstance(block, dict) and 'tx' in block and len(block['tx']) > 0:
                tx_hash = block['tx'][0] if isinstance(block['tx'][0], str) else str(block['tx'][0])
                try:
                    app_log = await provider.get_application_log(tx_hash)
                    print(f"   ✅ Success: Application log retrieved")
                except Exception as e:
                    print(f"   ⚠️  Application log not available: {str(e)[:50]}...")
        
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_transaction_tools():
    """Test transaction-related tools"""
    print("\n" + "=" * 70)
    print("Testing Transaction Tools")
    print("=" * 70)
    
    provider = Neo3Provider(network=NETWORK)
    
    try:
        # Get a recent block to find a transaction for testing
        block_count = await provider.get_block_count()
        test_tx_hash = None
        
        if block_count > 0:
            block = await provider.get_block(str(block_count - 1))
            if isinstance(block, dict) and 'tx' in block and len(block['tx']) > 0:
                test_tx_hash = block['tx'][0] if isinstance(block['tx'][0], str) else str(block['tx'][0])
        
        await provider.close()
        
        # Test GetRawMempoolTool
        print("\n1. Testing GetRawMempoolTool...")
        tool = GetRawMempoolTool()
        result = await tool.execute(0, NETWORK)
        if result.error:
            print(f"   ❌ Error: {result.error}")
        else:
            print(f"   ✅ Success: {result.output[:100]}...")
        
        # Test GetRawTransactionTool (if we have a transaction hash)
        if test_tx_hash:
            print("\n2. Testing GetRawTransactionTool...")
            tool = GetRawTransactionTool()
            result = await tool.execute(test_tx_hash, 0, NETWORK)
            if result.error:
                print(f"   ❌ Error: {result.error}")
            else:
                print(f"   ✅ Success: Transaction retrieved")
        else:
            print("\n2. Testing GetRawTransactionTool...")
            print(f"   ⚠️  Skipped (no transaction hash available)")
        
        # Test GetTransactionHeightTool (if we have a transaction hash)
        if test_tx_hash:
            print("\n3. Testing GetTransactionHeightTool...")
            tool = GetTransactionHeightTool()
            result = await tool.execute(test_tx_hash, NETWORK)
            if result.error:
                print(f"   ❌ Error: {result.error}")
            else:
                print(f"   ✅ Success: {result.output}")
        else:
            print("\n3. Testing GetTransactionHeightTool...")
            print(f"   ⚠️  Skipped (no transaction hash available)")
        
        # Test GetApplicationLogTool (if we have a transaction hash)
        if test_tx_hash:
            print("\n4. Testing GetApplicationLogTool...")
            tool = GetApplicationLogTool()
            result = await tool.execute(test_tx_hash, NETWORK)
            if result.error:
                print(f"   ⚠️  Application log not available: {result.error[:50]}...")
            else:
                print(f"   ✅ Success: Application log retrieved")
        else:
            print("\n4. Testing GetApplicationLogTool...")
            print(f"   ⚠️  Skipped (no transaction hash available)")
        
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()


@pytest.mark.asyncio
async def test_governance_tools():
    """Test governance-related tools"""
    print("\n" + "=" * 70)
    print("Testing Governance Tools")
    print("=" * 70)
    
    # Test GetCommitteeTool
    print("\n1. Testing GetCommitteeTool...")
    tool = GetCommitteeTool()
    result = await tool.execute(NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:150]}...")
    
    # Test GetCommitteeTool with provider for detailed output
    print("\n1b. Testing Neo3Provider.get_committee() directly...")
    provider = Neo3Provider(network=NETWORK)
    try:
        committee = await provider.get_committee()
        print(f"   ✅ Success: Committee retrieved")
        if isinstance(committee, list):
            print(f"   Committee members count: {len(committee)}")
            if committee:
                print(f"   First member (preview): {committee[0][:50]}...")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    
    # Test GetNativeContractsTool
    print("\n2. Testing GetNativeContractsTool...")
    tool = GetNativeContractsTool()
    result = await tool.execute(NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:150]}...")
    
    # Test GetNativeContractsTool with provider for detailed output
    print("\n2b. Testing Neo3Provider.get_native_contracts() directly...")
    provider = Neo3Provider(network=NETWORK)
    try:
        contracts = await provider.get_native_contracts()
        print(f"   ✅ Success: Native contracts retrieved")
        if isinstance(contracts, list):
            print(f"   Native contracts count: {len(contracts)}")
            if contracts:
                first_contract = contracts[0]
                if isinstance(first_contract, dict):
                    print(f"   First contract ID: {first_contract.get('id', 'N/A')}")
                    print(f"   First contract hash: {first_contract.get('hash', 'N/A')[:30]}...")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    
    # Test GetNextBlockValidatorsTool
    print("\n3. Testing GetNextBlockValidatorsTool...")
    tool = GetNextBlockValidatorsTool()
    result = await tool.execute(NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:150]}...")
    
    # Test GetNextBlockValidatorsTool with provider for detailed output
    print("\n3b. Testing Neo3Provider.get_next_block_validators() directly...")
    provider = Neo3Provider(network=NETWORK)
    try:
        validators = await provider.get_next_block_validators()
        print(f"   ✅ Success: Next block validators retrieved")
        if isinstance(validators, list):
            print(f"   Validators count: {len(validators)}")
            if validators:
                first_validator = validators[0]
                if isinstance(first_validator, dict):
                    print(f"   First validator public key: {first_validator.get('publickey', 'N/A')[:50]}...")
        await provider.close()
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")


@pytest.mark.asyncio
async def test_contract_tools():
    """Test contract-related tools"""
    print("\n" + "=" * 70)
    print("Testing Contract Tools")
    print("=" * 70)
    
    # NEO contract hash for mainnet/testnet
    neo_contract = "0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5"
    
    # Test GetContractStateTool
    print("\n1. Testing GetContractStateTool...")
    tool = GetContractStateTool()
    result = await tool.execute(neo_contract, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:150]}...")
    
    # Test GetNativeContractsTool
    print("\n2. Testing GetNativeContractsTool...")
    tool = GetNativeContractsTool()
    result = await tool.execute(NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:150]}...")
    
    # Test GetStorageTool (requires specific contract and key, skipping)
    print("\n3. Testing GetStorageTool...")
    print(f"   ⚠️  Skipped (requires specific contract and key)")
    
    # Test InvokeFunctionTool (requires specific contract and function, skipping)
    print("\n4. Testing InvokeFunctionTool...")
    print(f"   ⚠️  Skipped (requires specific contract and function)")


@pytest.mark.asyncio
async def test_contract_methods():
    """Test contract-related provider methods"""
    print("\n" + "=" * 70)
    print("Testing Contract Provider Methods")
    print("=" * 70)
    
    provider = Neo3Provider(network=NETWORK)
    
    try:
        # Test get_contract_state
        print("\n1. Testing get_contract_state (NEO contract)...")
        # NEO contract hash for mainnet/testnet
        neo_contract = "0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5"
        contract_state = await provider.get_contract_state(neo_contract)
        print(f"   ✅ Success: Contract state retrieved")
        if hasattr(contract_state, 'name'):
            print(f"   Contract name: {contract_state.name}")
        elif isinstance(contract_state, dict):
            print(f"   Contract name: {contract_state.get('name', 'N/A')}")
        
        # Test get_storage
        print("\n2. Testing get_storage...")
        # This requires a valid contract and key, skipping for now
        print(f"   ⚠️  Skipped (requires specific contract and key)")
        
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    finally:
        await provider.close()


async def run_all_tests():
    """Run all test suites"""
    print("\n" + "=" * 70)
    print(f"Neo N3 Blockchain Methods Test Suite")
    print(f"Network: {NETWORK}")
    print(f"Test Address: {TEST_ADDRESS}")
    print("=" * 70)
    
    try:
        await test_provider_methods()
        await test_nep_tools()
        await test_block_tools()
        await test_utility_tools()
        await test_transaction_methods()
        await test_transaction_tools()
        await test_governance_tools()
        await test_contract_tools()
        await test_contract_methods()
        
        print("\n" + "=" * 70)
        print("✅ All tests completed!")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(run_all_tests())

