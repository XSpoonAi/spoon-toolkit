# Neo N3 Blockchain Tools

This module provides tools for interacting with Neo N3 blockchain using **only official RPC API methods** as documented at [developers.neo.org](https://developers.neo.org/docs/n3/reference/rpc/api).

## 🎯 Key Difference from Neo Classic Tools

**Neo3 tools (`spoon_toolkits/crypto/neo3/`)**:
- ✅ Uses **only official Neo N3 RPC API methods**
- ✅ All methods are documented at: https://developers.neo.org/docs/n3/reference/rpc/api
- ✅ Guaranteed compatibility with any Neo N3 RPC node
- ✅ No dependency on third-party APIs or explorer services

**Neo classic tools (`spoon_toolkits/crypto/neo/`)**:
- ⚠️ Includes methods from third-party APIs (e.g., GetContractCount, GetNetworkStatistics, GetVerifiedContract)
- ⚠️ Some methods may not be available on all RPC nodes
- ⚠️ May depend on specific explorer services or extended APIs

## 📦 Available Tools

### Block Tools (`block_tools.py`)
- `GetBlockCountTool` - Get total number of blocks
- `GetBestBlockHashTool` - Get latest block hash
- `GetBlockByHashTool` - Get block by hash
- `GetBlockByHeightTool` - Get block by height
- `GetBlockHashTool` - Get block hash by index
- `GetBlockHeaderTool` - Get block header information

### Transaction Tools (`transaction_tools.py`)
- `GetRawTransactionTool` - Get transaction by hash
- `GetRawMempoolTool` - Get mempool transactions
- `GetTransactionHeightTool` - Get transaction block height
- `GetApplicationLogTool` - Get application log for transaction

### NEP Tools (`nep_tools.py`)
- `GetNep17BalancesTool` - Get NEP-17 token balances
- `GetNep17TransfersTool` - Get NEP-17 transfer history
- `GetNep11BalancesTool` - Get NEP-11 (NFT) balances
- `GetNep11PropertiesTool` - Get NEP-11 token properties
- `GetNep11TransfersTool` - Get NEP-11 transfer history

### Contract Tools (`contract_tools.py`)
- `GetContractStateTool` - Get contract state information
- `GetStorageTool` - Get contract storage value
- `InvokeFunctionTool` - Invoke smart contract function
- `GetNativeContractsTool` - Get list of native contracts

### Governance Tools (`governance_tools.py`)
- `GetCommitteeTool` - Get committee members
- `GetNextBlockValidatorsTool` - Get next block validators

### Utility Tools (`utility_tools.py`)
- `ValidateAddressTool` - Validate Neo address format

## 📚 Official RPC Methods Used

All tools in this module use only methods from the official Neo N3 RPC API:

### Blockchain Methods
- `getblockcount` - Get block count
- `getbestblockhash` - Get best block hash
- `getblock` - Get block by hash or index
- `getblockheader` - Get block header
- `getblockhash` - Get block hash by index

### Transaction Methods
- `getrawtransaction` - Get transaction by hash
- `getrawmempool` - Get mempool transactions
- `gettransactionheight` - Get transaction height
- `getapplicationlog` - Get application log

### Contract Methods
- `getcontractstate` - Get contract state
- `getstorage` - Get contract storage
- `invokefunction` - Invoke contract function
- `getnativecontracts` - Get native contracts

### NEP Methods (via TokensTracker plugin)
- `getnep17balances` - Get NEP-17 balances
- `getnep17transfers` - Get NEP-17 transfers
- `getnep11balances` - Get NEP-11 balances
- `getnep11properties` - Get NEP-11 properties
- `getnep11transfers` - Get NEP-11 transfers

### Governance Methods
- `getcommittee` - Get committee members
- `getnextblockvalidators` - Get next block validators

### Node Methods
- `getconnectioncount` - Get connection count
- `getpeers` - Get peer information
- `getversion` - Get node version

### State Methods (via StateService plugin)
- `getstateroot` - Get state root
- `getstateheight` - Get state height

### Smart Contract Methods
- `getunclaimedgas` - Get unclaimed gas

## 🧪 Testing

Each tool module has its own dedicated test file:

- `test_block_tools.py` - Tests for block tools
- `test_transaction_tools.py` - Tests for transaction tools
- `test_nep_tools.py` - Tests for NEP tools
- `test_contract_tools.py` - Tests for contract tools
- `test_governance_tools.py` - Tests for governance tools
- `test_utility_tools.py` - Tests for utility tools

### Running Tests

```bash
# Run all Neo3 tests
pytest tests/crypto/neo3/

# Run specific test file
pytest tests/crypto/neo3/test_block_tools.py

# Run specific test
pytest tests/crypto/neo3/test_block_tools.py::test_block_count -v
```

## 💡 Usage Examples

### Using Tools

```python
import asyncio
from spoon_toolkits.crypto.neo3 import (
    GetBlockCountTool,
    GetNep17BalancesTool,
    GetContractStateTool,
    GetCommitteeTool,
    ValidateAddressTool,
)

async def main():
    network = "mainnet"
    
    # Get block count
    block_tool = GetBlockCountTool()
    result = await block_tool.execute(network)
    print(result.output)
    
    # Get NEP-17 balances for an address
    address = "NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp"
    balance_tool = GetNep17BalancesTool()
    result = await balance_tool.execute(address, network)
    print(result.output)
    
    # Get contract state
    contract_hash = "0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5"  # NEO contract
    contract_tool = GetContractStateTool()
    result = await contract_tool.execute(contract_hash, network)
    print(result.output)
    
    # Validate address
    validate_tool = ValidateAddressTool()
    result = await validate_tool.execute(address, network)
    print(result.output)
    
    # Get committee members
    committee_tool = GetCommitteeTool()
    result = await committee_tool.execute(network)
    print(result.output)

asyncio.run(main())
```

### Using Provider Directly

```python
import asyncio
from spoon_toolkits.crypto.neo3 import Neo3Provider

async def main():
    network = "mainnet"
    provider = Neo3Provider(network=network)
    
    try:
        # Get block count
        block_count = await provider.get_block_count()
        print(f"Block count: {block_count}")
        
        # Get best block hash
        best_hash = await provider.get_best_block_hash()
        print(f"Best block hash: {best_hash}")
        
        # Get NEP-17 balances
        address = "NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp"
        balances = await provider.get_nep17_balances(address)
        print(f"NEP-17 balances: {balances}")
        
        # Get committee
        committee = await provider.get_committee()
        print(f"Committee members: {len(committee)}")
        
        # Get unclaimed gas
        unclaimed_gas = await provider.get_unclaimed_gas(address)
        print(f"Unclaimed gas: {unclaimed_gas}")
        
    finally:
        await provider.close()

asyncio.run(main())
```

### Complete Address Information Example

```python
import asyncio
from spoon_toolkits.crypto.neo3 import Neo3Provider

async def get_address_info(address: str, network: str = "mainnet"):
    """Get comprehensive address information"""
    provider = Neo3Provider(network=network)
    
    try:
        # Validate address
        is_valid = provider.validate_address(address)
        print(f"Address valid: {is_valid}")
        
        # Get NEP-17 balances
        nep17_balances = await provider.get_nep17_balances(address)
        print(f"NEP-17 balances retrieved")
        
        # Get NEP-11 balances
        nep11_balances = await provider.get_nep11_balances(address)
        print(f"NEP-11 balances retrieved")
        
        # Get NEP-17 transfers
        nep17_transfers = await provider.get_nep17_transfers(address)
        print(f"NEP-17 transfers retrieved")
        
        # Get NEP-11 transfers
        nep11_transfers = await provider.get_nep11_transfers(address)
        print(f"NEP-11 transfers retrieved")
        
        # Get unclaimed gas
        unclaimed_gas = await provider.get_unclaimed_gas(address)
        print(f"Unclaimed gas: {unclaimed_gas}")
        
    finally:
        await provider.close()

# Usage
asyncio.run(get_address_info("NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp", "mainnet"))
```

### Transaction and Block Examples

```python
import asyncio
from spoon_toolkits.crypto.neo3 import (
    Neo3Provider,
    GetRawTransactionTool,
    GetBlockByHeightTool,
    GetRawMempoolTool,
)

async def main():
    network = "mainnet"
    
    # Get latest block
    provider = Neo3Provider(network=network)
    block_count = await provider.get_block_count()
    await provider.close()
    
    block_tool = GetBlockByHeightTool()
    result = await block_tool.execute(block_count - 1, 0, network)
    print(f"Latest block: {result.output[:200]}...")
    
    # Get mempool
    mempool_tool = GetRawMempoolTool()
    result = await mempool_tool.execute(0, network)
    print(f"Mempool: {result.output[:200]}...")

asyncio.run(main())
```

## 📖 Reference

- Official Neo N3 RPC API Documentation: https://developers.neo.org/docs/n3/reference/rpc/api
- Neo N3 Developer Documentation: https://developers.neo.org/docs/n3

