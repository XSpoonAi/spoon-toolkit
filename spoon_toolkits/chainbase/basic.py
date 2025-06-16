import os
import traceback
from typing import List, Optional

import requests
from fastmcp import FastMCP, Context
from fastmcp.resources import TextResource

# Get API key from environment variable
api_key = os.getenv("CHAINBASE_API_KEY", "")
base_url = "https://api.chainbase.online/v1"
mcp = FastMCP(name="ChainbaseBasicServer")

@mcp.tool()
async def get_latest_block_number(ctx: Context = None, chain_id: int = 1):
    """Get the latest block height of blockchain network.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
    returns:
        block_number: int
    """
    try:
        url = f"{base_url}/block/number/latest"
        headers = {"x-api-key": api_key}
        querystring = {"chain_id":int(chain_id)}
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting latest block number: {e}")
        return None
    
@mcp.tool()
async def get_block_by_number(ctx: Context = None, chain_id: int = 1, number: int = 1):
    """Get the block by number of blockchain network.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        number[Required][int]: block number
    returns:    
        block: dict
    """
    try:

        url = f"{base_url}/block/detail"
        headers = {"x-api-key": api_key}
        querystring = {"chain_id":int(chain_id), "number":int(number)}
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting block by number: {e}")
        return None

@mcp.tool()
async def get_transaction_by_hash(ctx: Context = None, chain_id: int = 1, 
                            hash: Optional[str] = None,
                            block_number: Optional[int] = None,
                            tx_index: Optional[int] = None):
    """Get the transaction by hash of blockchain network.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        hash[Optional][str]: transaction hash
        block_number[Optional][str]: Block number of the transaction, if not provided the hash, should be provided with tx_index
        tx_index[Optional][str]: Transaction index of the block, if not provided the hash, should be provided with block_number
    returns:
        transaction: dict
    """
    try:
        url = f"{base_url}/tx/detail"
        headers = {"x-api-key": api_key}
        querystring = {"chain_id":int(chain_id)}
        if hash:
            querystring["hash"] = hash
        if block_number:
            querystring["block_number"] = int(block_number)
        if tx_index:
            querystring["tx_index"] = int(tx_index)
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting transaction by hash: {e}")
        return None
    
@mcp.tool()
async def get_transactions_by_account(ctx: Context = None, chain_id: int = 1, address: str = None, 
                                     from_block: Optional[str] = None, to_block: Optional[str] = None,
                                     from_timestamp: Optional[int] = None, end_timestamp: Optional[int] = None,
                                     page: int = 1, limit: int = 10):
    """Returns the transactions from the address.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        address[Required][str]: A hex string referencing a wallet address
        from_block[Optional][str]: Inclusive from block number (hex string or int)
        to_block[Optional][str]: Inclusive to block number (hex string, int, or 'latest')
        from_timestamp[Optional][int]: Inclusive from block number (hex string or int)
        end_timestamp[Optional][int]: Inclusive end timestamp
        page[Optional][int]: The page offset, default is 1
        limit[Optional][int]: The desired page size limit. Less or equal than 100, default is 10
        
    returns:
        transactions: list
    """
    try:
        url = f"{base_url}/account/txs"
        headers = {"x-api-key": api_key}
        
        # Build query parameters
        querystring = {"chain_id": int(chain_id), "address": address, "page": page, "limit": limit}
        
        # Add optional parameters
        if from_block:
            querystring["from_block"] = from_block
        if to_block:
            querystring["to_block"] = to_block
        if from_timestamp:
            querystring["from_timestamp"] = from_timestamp
        if end_timestamp:
            querystring["end_timestamp"] = end_timestamp
            
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting transactions by account: {e}")
        ctx.log.error(traceback.format_exc())
        return None
    
@mcp.tool()
async def contract_calls(ctx: Context = None, chain_id: int = 1, contract_address: str = None, 
                         function_name: str = None, abi: str = None, params: List = None, 
                         to_block: str = "latest"):
    """Calls a specific function for the specified contract.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        contract_address[Required][str]: A hex string referencing a contract address
        function_name[Required][str]: The name of the function to call
        abi[Required][str]: The ABI of the contract function
        params[Required][list]: The parameters to pass to the function
        to_block[Required][str]: Block number to execute the call at (can be a number or 'latest')
    returns:
        result: dict containing the function call result
    """
    try:
        url = f"{base_url}/contract/call"
        headers = {
            "x-api-key": api_key,
            "Content-Type": "application/json"
        }
        
        # Build request payload
        payload = {
            "chain_id": int(chain_id),
            "contract_address": contract_address,
            "function_name": function_name,
            "abi": abi,
            "params": params if params else [],
            "to_block": to_block
        }
        
        response = requests.request("POST", url, json=payload, headers=headers)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error calling contract function: {e}")
        ctx.log.error(traceback.format_exc())
        return None

supported_chains = [
    {"chain": "Ethereum", "network_id": 1},
    {"chain": "Polygon", "network_id": 137},
    {"chain": "BSC", "network_id": 56},
    {"chain": "Avalanche", "network_id": 43114},
    {"chain": "Arbitrum One", "network_id": 42161},
    {"chain": "Optimism", "network_id": 10},
    {"chain": "Base", "network_id": 8453},
    {"chain": "zkSync", "network_id": 324},
    {"chain": "Merlin", "network_id": 4200}
]

# Register supported blockchain information using TextResource
supported_chains_resource = TextResource(
    uri="resource://chainbase/supported-chains",
    name="Supported Blockchain Networks",
    description="List of blockchain networks supported by Chainbase API with their network IDs",
    text=str(supported_chains),
    mime_type="application/json",
    tags={"blockchain", "chainbase", "reference"}
)
mcp.add_resource(supported_chains_resource)

# Also provide a function-based resource that returns more formatted JSON
@mcp.resource(
    uri="data://chainbase/supported-chains",
    name="Supported Blockchain Networks",
    description="List of blockchain networks supported by Chainbase API with their network IDs",
    mime_type="application/json",
    tags={"blockchain", "chainbase", "reference"}
)
def get_supported_chains():
    """Returns the list of supported blockchain networks with their network IDs."""
    return supported_chains

# Add documentation resources for basic APIs
@mcp.resource(
    uri="doc://chainbase/latest-block-number",
    name="Latest Block Number API Documentation",
    description="Documentation for the Chainbase Latest Block Number API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "block"}
)
def get_latest_block_number_docs():
    """Returns documentation for the Latest Block Number API endpoint."""
    return """
    # Latest Block Number API
    
    Get the latest block height of blockchain network.
    
    ## Endpoint
    
    `GET /v1/block/number/latest`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": {
        "number": 123,
        "hash": "<string>"
      }
    }
    ```
    """

@mcp.resource(
    uri="doc://chainbase/block-by-number",
    name="Block By Number API Documentation",
    description="Documentation for the Chainbase Block By Number API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "block"}
)
def get_block_by_number_docs():
    """Returns documentation for the Block By Number API endpoint."""
    return """
    # Block By Number API
    
    Get the block by number of blockchain network.
    
    ## Endpoint
    
    `GET /v1/block/detail`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `number` (required): Block number
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": {
        "number": 123,
        "hash": "0x...",
        "parent_hash": "0x...",
        "timestamp": 1629700000,
        "transactions": ["0x...", "0x..."],
        "size": 1234,
        "gas_used": 1000000,
        "gas_limit": 2000000
      }
    }
    ```
    """

@mcp.resource(
    uri="doc://chainbase/transaction-by-hash",
    name="Transaction By Hash API Documentation",
    description="Documentation for the Chainbase Transaction By Hash API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "transaction"}
)
def get_transaction_by_hash_docs():
    """Returns documentation for the Transaction By Hash API endpoint."""
    return """
    # Transaction By Hash API
    
    Get the transaction by hash of blockchain network.
    
    ## Endpoint
    
    `GET /v1/tx/detail`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `hash` (optional): Transaction hash
    - `block_number` (optional): Block number of the transaction, if not provided the hash, should be provided with tx_index
    - `tx_index` (optional): Transaction index of the block, if not provided the hash, should be provided with block_number
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": {
        "hash": "0x...",
        "block_hash": "0x...",
        "block_number": "12345678",
        "block_timestamp": 1629700000,
        "from_address": "0x...",
        "to_address": "0x...",
        "value": "1000000000000000000",
        "gas": 21000,
        "gas_price": "5000000000",
        "input": "0x...",
        "nonce": 123,
        "transaction_index": 10,
        "status": 1
      }
    }
    ```
    """

@mcp.resource(
    uri="doc://chainbase/transactions-by-account",
    name="Transactions By Account API Documentation",
    description="Documentation for the Chainbase Transactions By Account API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "transaction", "account"}
)
def get_transactions_by_account_docs():
    """Returns documentation for the Transactions By Account API endpoint."""
    return """
    # Transactions By Account API
    
    Returns the transactions from the address.
    
    ## Endpoint
    
    `GET /v1/account/txs`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `address` (required): A hex string referencing a wallet address
    - `from_block` (optional): Inclusive from block number (hex string or int)
    - `to_block` (optional): Inclusive to block number (hex string, int, or 'latest')
    - `from_timestamp` (optional): Inclusive start timestamp
    - `end_timestamp` (optional): Inclusive end timestamp
    - `page` (optional): The page offset, default is 1
    - `limit` (optional): The desired page size limit. Less or equal than 100, default is 10
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": [
        {
          "hash": "0x...",
          "block_hash": "0x...",
          "block_number": "12345678",
          "block_timestamp": 1629700000,
          "from_address": "0x...",
          "to_address": "0x...",
          "value": "1000000000000000000",
          "gas": 21000,
          "gas_price": "5000000000",
          "input": "0x...",
          "nonce": 123,
          "transaction_index": 10,
          "status": 1
        }
      ],
      "next_page": 2,
      "count": 100
    }
    ```
    """

@mcp.resource(
    uri="doc://chainbase/contract-calls",
    name="Contract Calls API Documentation",
    description="Documentation for the Chainbase Contract Calls API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "contract", "function"}
)
def get_contract_calls_docs():
    """Returns documentation for the Contract Calls API endpoint."""
    return """
    # Contract Calls API
    
    Calls a specific function for the specified contract.
    
    ## Endpoint
    
    `POST /v1/contract/call`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `contract_address` (required): A hex string referencing a contract address
    - `function_name` (required): The name of the function to call
    - `abi` (required): The ABI of the contract function
    - `params` (required): The parameters to pass to the function
    - `to_block` (required): Block number to execute the call at (can be a number or 'latest')
    
    ## Request Body Example
    
    ```json
    {
      "chain_id": 1,
      "contract_address": "0x...",
      "function_name": "balanceOf",
      "abi": "[{\"constant\":true,\"inputs\":[{\"name\":\"_owner\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"name\":\"balance\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"}]",
      "params": ["0x..."],
      "to_block": "latest"
    }
    ```
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": {
        "result": "1000000000000000000"
      }
    }
    ```
    """

# Add health check route
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    from starlette.responses import JSONResponse
    return JSONResponse({"status": "ok", "service": "ChainbaseToolsServer"})

if __name__ == "__main__":
    # Print confirmation that API key is set
    if not os.environ.get("CHAINBASE_API_KEY"):
        api_key = "2yZuGx0TrNSY7VWsi5iZcIVbg72"
    
    # Start FastMCP server with SSE transport protocol
    mcp.run(
        transport="sse",
        host="0.0.0.0",  # Listen on all network interfaces
        port=8765,       # Port
        log_level="info", # Log level
        path="/sse"      # SSE path
    )