"""Comprehensive test script for Neo N3 address information

Tests NEP-17 and NEP-11 balances and transfers for a specific address.
This includes both tool-based and provider-based methods.

Usage:
    # Method 1: Run directly (from project root)
    python tests/crypto/neo3/test_neo_address_info.py
    
    # Method 2: Run with pytest
    pytest tests/crypto/neo3/test_neo_address_info.py
    
    # Method 3: Run a specific test with pytest
    pytest tests/crypto/neo3/test_neo_address_info.py::test_address_balances -v
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
    GetNep17BalancesTool,
    GetNep17TransfersTool,
    GetNep11BalancesTool,
    GetNep11TransfersTool,
    ValidateAddressTool,
)


# Test configuration
TEST_ADDRESS = "NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp"  # Change to your test address
NETWORK = "mainnet"  # or "testnet"


def format_balance(balance_data):
    """Format balance data for display"""
    if isinstance(balance_data, dict):
        return json.dumps(balance_data, indent=2)
    elif hasattr(balance_data, '__dict__'):
        return json.dumps(balance_data.__dict__, indent=2, default=str)
    else:
        return str(balance_data)


def format_transfer(transfer_data):
    """Format transfer data for display"""
    if isinstance(transfer_data, dict):
        return json.dumps(transfer_data, indent=2)
    elif hasattr(transfer_data, '__dict__'):
        return json.dumps(transfer_data.__dict__, indent=2, default=str)
    else:
        return str(transfer_data)


@pytest.mark.asyncio
async def test_address_validation():
    """Test address validation"""
    print("=" * 70)
    print("Testing Address Validation")
    print("=" * 70)
    
    # Test ValidateAddressTool
    print(f"\n1. Testing ValidateAddressTool for: {TEST_ADDRESS}")
    tool = ValidateAddressTool()
    result = await tool.execute(TEST_ADDRESS, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: {result.output}")
    
    # Test with provider
    print(f"\n2. Testing Neo3Provider.validate_address() for: {TEST_ADDRESS}")
    provider = Neo3Provider(network=NETWORK)
    try:
        is_valid = provider.validate_address(TEST_ADDRESS)
        print(f"   ✅ Success: Address is {'valid' if is_valid else 'invalid'}")
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_nep17_balances():
    """Test NEP-17 token balances"""
    print("\n" + "=" * 70)
    print("Testing NEP-17 Token Balances")
    print("=" * 70)
    print(f"Address: {TEST_ADDRESS}")
    print(f"Network: {NETWORK}")
    
    # Test using GetNep17BalancesTool
    print("\n1. Testing GetNep17BalancesTool...")
    tool = GetNep17BalancesTool()
    result = await tool.execute(TEST_ADDRESS, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    # Test using provider directly for detailed output
    print("\n2. Testing Neo3Provider.get_nep17_balances() directly...")
    provider = Neo3Provider(network=NETWORK)
    try:
        balances_response = await provider.get_nep17_balances(TEST_ADDRESS)
        print(f"   ✅ Success: Response received")
        
        # Parse and display balances
        if hasattr(balances_response, 'balances'):
            balances_list = balances_response.balances
            print(f"\n   📊 NEP-17 Token Balances: {len(balances_list)} tokens")
            
            if balances_list:
                for i, balance in enumerate(balances_list, 1):
                    print(f"\n   Token {i}:")
                    balance_str = format_balance(balance)
                    # Show first few lines of formatted balance
                    lines = balance_str.split('\n')[:5]
                    for line in lines:
                        print(f"      {line}")
                    if len(balance_str.split('\n')) > 5:
                        print(f"      ... ({len(balance_str.split('\n')) - 5} more lines)")
            else:
                print(f"\n   ⚠️  No NEP-17 token balances found for this address.")
        else:
            print(f"   Response type: {type(balances_response)}")
            print(f"   Response: {format_balance(balances_response)[:200]}...")
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_nep11_balances():
    """Test NEP-11 token (NFT) balances"""
    print("\n" + "=" * 70)
    print("Testing NEP-11 Token (NFT) Balances")
    print("=" * 70)
    print(f"Address: {TEST_ADDRESS}")
    print(f"Network: {NETWORK}")
    
    # Test using GetNep11BalancesTool
    print("\n1. Testing GetNep11BalancesTool...")
    tool = GetNep11BalancesTool()
    result = await tool.execute(TEST_ADDRESS, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    # Test using provider directly for detailed output
    print("\n2. Testing Neo3Provider.get_nep11_balances() directly...")
    provider = Neo3Provider(network=NETWORK)
    try:
        balances_response = await provider.get_nep11_balances(TEST_ADDRESS)
        print(f"   ✅ Success: Response received")
        
        # Parse and display balances
        if isinstance(balances_response, dict):
            if 'balance' in balances_response:
                balance_list = balances_response['balance']
                print(f"\n   📊 NEP-11 Token (NFT) Balances: {len(balance_list) if isinstance(balance_list, list) else 'N/A'} items")
                
                if isinstance(balance_list, list) and balance_list:
                    for i, balance in enumerate(balance_list[:5], 1):  # Show first 5
                        print(f"\n   NFT {i}:")
                        balance_str = format_balance(balance)
                        lines = balance_str.split('\n')[:5]
                        for line in lines:
                            print(f"      {line}")
                        if len(balance_str.split('\n')) > 5:
                            print(f"      ... ({len(balance_str.split('\n')) - 5} more lines)")
                    if len(balance_list) > 5:
                        print(f"\n   ... ({len(balance_list) - 5} more NFTs)")
                else:
                    print(f"\n   ⚠️  No NEP-11 token balances found for this address.")
            else:
                print(f"   Response structure: {format_balance(balances_response)[:300]}...")
        else:
            print(f"   Response type: {type(balances_response)}")
            print(f"   Response: {format_balance(balances_response)[:200]}...")
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_nep17_transfers():
    """Test NEP-17 token transfers"""
    print("\n" + "=" * 70)
    print("Testing NEP-17 Token Transfers")
    print("=" * 70)
    print(f"Address: {TEST_ADDRESS}")
    print(f"Network: {NETWORK}")
    
    # Test using GetNep17TransfersTool
    print("\n1. Testing GetNep17TransfersTool (all transfers)...")
    tool = GetNep17TransfersTool()
    result = await tool.execute(TEST_ADDRESS, None, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    # Test using provider directly for detailed output
    print("\n2. Testing Neo3Provider.get_nep17_transfers() directly...")
    provider = Neo3Provider(network=NETWORK)
    try:
        transfers_response = await provider.get_nep17_transfers(TEST_ADDRESS)
        print(f"   ✅ Success: Response received")
        
        # Parse and display transfers
        if isinstance(transfers_response, dict):
            sent = transfers_response.get('sent', [])
            received = transfers_response.get('received', [])
            
            print(f"\n   📊 NEP-17 Transfer Summary:")
            print(f"      Sent: {len(sent) if isinstance(sent, list) else 0} transfers")
            print(f"      Received: {len(received) if isinstance(received, list) else 0} transfers")
            
            if isinstance(sent, list) and sent:
                print(f"\n   📤 Recent Sent Transfers (showing first 3):")
                for i, transfer in enumerate(sent[:3], 1):
                    print(f"\n   Transfer {i}:")
                    transfer_str = format_transfer(transfer)
                    lines = transfer_str.split('\n')[:4]
                    for line in lines:
                        print(f"      {line}")
                    if len(transfer_str.split('\n')) > 4:
                        print(f"      ... ({len(transfer_str.split('\n')) - 4} more lines)")
            
            if isinstance(received, list) and received:
                print(f"\n   📥 Recent Received Transfers (showing first 3):")
                for i, transfer in enumerate(received[:3], 1):
                    print(f"\n   Transfer {i}:")
                    transfer_str = format_transfer(transfer)
                    lines = transfer_str.split('\n')[:4]
                    for line in lines:
                        print(f"      {line}")
                    if len(transfer_str.split('\n')) > 4:
                        print(f"      ... ({len(transfer_str.split('\n')) - 4} more lines)")
            
            if (not isinstance(sent, list) or not sent) and (not isinstance(received, list) or not received):
                print(f"\n   ⚠️  No NEP-17 transfers found for this address.")
        else:
            print(f"   Response type: {type(transfers_response)}")
            print(f"   Response: {format_transfer(transfers_response)[:200]}...")
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_nep11_transfers():
    """Test NEP-11 token (NFT) transfers"""
    print("\n" + "=" * 70)
    print("Testing NEP-11 Token (NFT) Transfers")
    print("=" * 70)
    print(f"Address: {TEST_ADDRESS}")
    print(f"Network: {NETWORK}")
    
    # Test using GetNep11TransfersTool
    print("\n1. Testing GetNep11TransfersTool (all transfers)...")
    tool = GetNep11TransfersTool()
    result = await tool.execute(TEST_ADDRESS, None, NETWORK)
    if result.error:
        print(f"   ❌ Error: {result.error}")
    else:
        print(f"   ✅ Success: Tool executed")
        print(f"   Output preview: {result.output[:200]}...")
    
    # Test using provider directly for detailed output
    print("\n2. Testing Neo3Provider.get_nep11_transfers() directly...")
    provider = Neo3Provider(network=NETWORK)
    try:
        transfers_response = await provider.get_nep11_transfers(TEST_ADDRESS)
        print(f"   ✅ Success: Response received")
        
        # Parse and display transfers
        if isinstance(transfers_response, dict):
            sent = transfers_response.get('sent', [])
            received = transfers_response.get('received', [])
            
            print(f"\n   📊 NEP-11 Transfer Summary:")
            print(f"      Sent: {len(sent) if isinstance(sent, list) else 0} transfers")
            print(f"      Received: {len(received) if isinstance(received, list) else 0} transfers")
            
            if isinstance(sent, list) and sent:
                print(f"\n   📤 Recent Sent NFT Transfers (showing first 3):")
                for i, transfer in enumerate(sent[:3], 1):
                    print(f"\n   Transfer {i}:")
                    transfer_str = format_transfer(transfer)
                    lines = transfer_str.split('\n')[:4]
                    for line in lines:
                        print(f"      {line}")
                    if len(transfer_str.split('\n')) > 4:
                        print(f"      ... ({len(transfer_str.split('\n')) - 4} more lines)")
            
            if isinstance(received, list) and received:
                print(f"\n   📥 Recent Received NFT Transfers (showing first 3):")
                for i, transfer in enumerate(received[:3], 1):
                    print(f"\n   Transfer {i}:")
                    transfer_str = format_transfer(transfer)
                    lines = transfer_str.split('\n')[:4]
                    for line in lines:
                        print(f"      {line}")
                    if len(transfer_str.split('\n')) > 4:
                        print(f"      ... ({len(transfer_str.split('\n')) - 4} more lines)")
            
            if (not isinstance(sent, list) or not sent) and (not isinstance(received, list) or not received):
                print(f"\n   ⚠️  No NEP-11 transfers found for this address.")
        else:
            print(f"   Response type: {type(transfers_response)}")
            print(f"   Response: {format_transfer(transfers_response)[:200]}...")
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_unclaimed_gas():
    """Test unclaimed gas for address"""
    print("\n" + "=" * 70)
    print("Testing Unclaimed Gas")
    print("=" * 70)
    print(f"Address: {TEST_ADDRESS}")
    print(f"Network: {NETWORK}")
    
    provider = Neo3Provider(network=NETWORK)
    
    try:
        print("\n1. Testing Neo3Provider.get_unclaimed_gas()...")
        unclaimed_gas = await provider.get_unclaimed_gas(TEST_ADDRESS)
        print(f"   ✅ Success: Unclaimed gas retrieved")
        print(f"   Unclaimed Gas: {unclaimed_gas}")
        
        # Try to format as number if possible
        try:
            gas_value = int(unclaimed_gas) if isinstance(unclaimed_gas, str) and unclaimed_gas.isdigit() else unclaimed_gas
            if isinstance(gas_value, int):
                # Convert from smallest unit to GAS (8 decimals)
                gas_amount = gas_value / 100000000
                print(f"   Unclaimed Gas Amount: {gas_amount} GAS")
        except:
            pass
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_complete_address_info():
    """Test complete address information summary"""
    print("\n" + "=" * 70)
    print("Complete Address Information Summary")
    print("=" * 70)
    print(f"Address: {TEST_ADDRESS}")
    print(f"Network: {NETWORK}")
    
    provider = Neo3Provider(network=NETWORK)
    
    try:
        # Validate address
        print("\n📍 Address Validation:")
        is_valid = provider.validate_address(TEST_ADDRESS)
        print(f"   Status: {'✅ Valid' if is_valid else '❌ Invalid'}")
        
        # Get NEP-17 balances
        print("\n💰 NEP-17 Token Balances:")
        nep17_balances = await provider.get_nep17_balances(TEST_ADDRESS)
        if hasattr(nep17_balances, 'balances'):
            balance_count = len(nep17_balances.balances)
            print(f"   Count: {balance_count} tokens")
        else:
            print(f"   Status: Retrieved")
        
        # Get NEP-11 balances
        print("\n🎨 NEP-11 Token (NFT) Balances:")
        nep11_balances = await provider.get_nep11_balances(TEST_ADDRESS)
        if isinstance(nep11_balances, dict) and 'balance' in nep11_balances:
            nft_count = len(nep11_balances['balance']) if isinstance(nep11_balances['balance'], list) else 0
            print(f"   Count: {nft_count} NFTs")
        else:
            print(f"   Status: Retrieved")
        
        # Get NEP-17 transfers summary
        print("\n📤📥 NEP-17 Transfer History:")
        nep17_transfers = await provider.get_nep17_transfers(TEST_ADDRESS)
        if isinstance(nep17_transfers, dict):
            sent_count = len(nep17_transfers.get('sent', [])) if isinstance(nep17_transfers.get('sent'), list) else 0
            received_count = len(nep17_transfers.get('received', [])) if isinstance(nep17_transfers.get('received'), list) else 0
            print(f"   Sent: {sent_count} transfers")
            print(f"   Received: {received_count} transfers")
        
        # Get NEP-11 transfers summary
        print("\n🎨📤📥 NEP-11 Transfer History:")
        nep11_transfers = await provider.get_nep11_transfers(TEST_ADDRESS)
        if isinstance(nep11_transfers, dict):
            sent_count = len(nep11_transfers.get('sent', [])) if isinstance(nep11_transfers.get('sent'), list) else 0
            received_count = len(nep11_transfers.get('received', [])) if isinstance(nep11_transfers.get('received'), list) else 0
            print(f"   Sent: {sent_count} transfers")
            print(f"   Received: {received_count} transfers")
        
        # Get unclaimed gas
        print("\n⛽ Unclaimed Gas:")
        try:
            unclaimed_gas = await provider.get_unclaimed_gas(TEST_ADDRESS)
            print(f"   Amount: {unclaimed_gas}")
            # Try to format as GAS amount
            try:
                gas_value = int(unclaimed_gas) if isinstance(unclaimed_gas, str) and unclaimed_gas.isdigit() else unclaimed_gas
                if isinstance(gas_value, int):
                    gas_amount = gas_value / 100000000
                    print(f"   Formatted: {gas_amount} GAS")
            except:
                pass
        except Exception as e:
            print(f"   ⚠️  Error retrieving unclaimed gas: {str(e)[:50]}...")
        
        print("\n" + "=" * 70)
        print("✅ Complete address information retrieved successfully!")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await provider.close()


async def run_all_tests():
    """Run all address information tests"""
    print("\n" + "=" * 70)
    print(f"Neo N3 Address Information Test Suite")
    print(f"Network: {NETWORK}")
    print(f"Test Address: {TEST_ADDRESS}")
    print("=" * 70)
    
    try:
        await test_address_validation()
        await test_nep17_balances()
        await test_nep11_balances()
        await test_nep17_transfers()
        await test_nep11_transfers()
        await test_unclaimed_gas()
        await test_complete_address_info()
        
        print("\n" + "=" * 70)
        print("✅ All address information tests completed!")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(run_all_tests())

