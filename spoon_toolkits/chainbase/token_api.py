import os
import traceback
from typing import Optional

import requests
from fastmcp import FastMCP, Context

# Get API key from environment variable
api_key = os.getenv("CHAINBASE_API_KEY", "")
base_url = "https://api.chainbase.online/v1"
mcp = FastMCP(name="ChainbaseTokenAPIServer")

@mcp.tool()
async def get_token_metadata(ctx: Context = None, chain_id: int = 1, 
                            contract_address: str = None):
    """Get the metadata of a specified token.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        contract_address[Required][str]: The address of the token contract
    returns:
        metadata: dict containing token metadata information
    """
    try:
        url = f"{base_url}/token/metadata"
        headers = {"x-api-key": api_key}
        
        # 构建查询参数
        querystring = {
            "chain_id": int(chain_id),
            "contract_address": contract_address
        }
            
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting token metadata: {e}")
        ctx.log.error(traceback.format_exc())
        return None

@mcp.tool()
async def get_token_top_holders(ctx: Context = None, chain_id: int = 1,
                               contract_address: str = None,
                               page: int = 1, limit: int = 20):
    """Get the list of top holders of the specified contract.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        contract_address[Required][str]: The address of the token contract
        page[Optional][int]: The page offset, default is 1
        limit[Optional][int]: The desired page size limit. Less or equal than 100, default is 20
    returns:
        holders: dict containing top token holders information
    """
    try:
        url = f"{base_url}/token/top-holders"
        headers = {"x-api-key": api_key}
        
        # 构建查询参数
        querystring = {
            "chain_id": int(chain_id),
            "contract_address": contract_address,
            "page": max(page, 1),       # Ensure page number is at least 1
            "limit": min(limit, 100)    # Ensure not exceeding API limit
        }
            
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting token top holders: {e}")
        ctx.log.error(traceback.format_exc())
        return None

@mcp.tool()
async def get_token_holders(ctx: Context = None, chain_id: int = 1,
                           contract_address: str = None,
                           page: int = 1, limit: int = 20):
    """Get the list of holders of the specified contract.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        contract_address[Required][str]: The address of the token contract
        page[Optional][int]: The page offset, default is 1
        limit[Optional][int]: The desired page size limit. Less or equal than 100, default is 20
    returns:
        holders: dict containing all token holders information
    """
    try:
        url = f"{base_url}/token/holders"
        headers = {"x-api-key": api_key}
        
        # 构建查询参数
        querystring = {
            "chain_id": int(chain_id),
            "contract_address": contract_address,
            "page": max(page, 1),       # Ensure page number is at least 1
            "limit": min(limit, 100)    # Ensure not exceeding API limit
        }
            
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting token holders: {e}")
        ctx.log.error(traceback.format_exc())
        return None

@mcp.tool()
async def get_token_price(ctx: Context = None, chain_id: int = 1,
                          contract_address: str = None):
    """Get the price of the specified token.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        contract_address[Required][str]: The address of the token contract
    returns:
        price: dict containing token price information
    """
    try:
        url = f"{base_url}/token/price"
        headers = {"x-api-key": api_key}
        
        # 构建查询参数
        querystring = {
            "chain_id": int(chain_id),
            "contract_address": contract_address
        }
            
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting token price: {e}")
        ctx.log.error(traceback.format_exc())
        return None

@mcp.tool()
async def get_token_price_history(ctx: Context = None, chain_id: int = 1,
                                 contract_address: str = None,
                                 from_timestamp: int = None,
                                 end_timestamp: int = None):
    """Get the historical price of the specified token.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        contract_address[Required][str]: The address of the token contract
        from_timestamp[Required][int]: Inclusive start timestamp
        end_timestamp[Required][int]: Inclusive end timestamp, the interval should not exceed 90 days
    returns:
        price_history: dict containing historical token price information
    """
    try:
        url = f"{base_url}/token/price/history"
        headers = {"x-api-key": api_key}
        
        # 构建查询参数
        querystring = {
            "chain_id": int(chain_id),
            "contract_address": contract_address,
            "from_timestamp": from_timestamp,
            "end_timestamp": end_timestamp
        }
            
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting token price history: {e}")
        ctx.log.error(traceback.format_exc())
        return None

@mcp.tool()
async def get_token_transfers(ctx: Context = None, chain_id: int = 1,
                             contract_address: Optional[str] = None,
                             address: Optional[str] = None,
                             from_block: Optional[str] = None,
                             to_block: Optional[str] = None,
                             from_timestamp: Optional[int] = None,
                             end_timestamp: Optional[int] = None,
                             page: int = 1, limit: int = 20):
    """Retrieves historical token transfer transactions for any ERC20 contract.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        contract_address[Optional][str]: The address of the token contract
        address[Optional][str]: A hex string referencing a wallet address
        from_block[Optional][str]: Inclusive from block number (hex string or int)
        to_block[Optional][str]: Inclusive to block number (hex string, int, or 'latest')
        from_timestamp[Optional][int]: Inclusive start timestamp
        end_timestamp[Optional][int]: Inclusive end timestamp
        page[Optional][int]: The page offset, default is 1
        limit[Optional][int]: The desired page size limit. Less or equal than 100, default is 20
    returns:
        transfers: dict containing token transfer information
    """
    try:
        url = f"{base_url}/token/transfers"
        headers = {"x-api-key": api_key}
        
        # 构建查询参数
        querystring = {
            "chain_id": int(chain_id),
            "page": max(page, 1),       # Ensure page number is at least 1
            "limit": min(limit, 100)    # Ensure not exceeding API limit
        }
        
        # Add optional parameters
        if contract_address:
            querystring["contract_address"] = contract_address
        if address:
            querystring["address"] = address
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
        ctx.log.error(f"Error getting token transfers: {e}")
        ctx.log.error(traceback.format_exc())
        return None

@mcp.resource(
    uri="doc://chainbase/token-metadata",
    name="Token Metadata API Documentation",
    description="Documentation for the Chainbase Token Metadata API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "token", "metadata"}
)
def get_token_metadata_docs():
    """Returns documentation for the Token Metadata API endpoint."""
    return """
    # Token Metadata API
    
    Get the metadata of a specified token.
    
    ## Endpoint
    
    `GET /v1/token/metadata`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `contract_address` (required): The address of the token contract
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": {
        // Token metadata information
        "name": "Token Name",
        "symbol": "TKN",
        "decimals": 18,
        "total_supply": "1000000000000000000000000",
        "contract_address": "0x...",
        "logo": "https://...",
        "official_site": "https://...",
        "social_profiles": {
          "twitter": "https://...",
          "telegram": "https://..."
        }
      }
    }
    ```
    """

@mcp.resource(
    uri="doc://chainbase/token-top-holders",
    name="Token Top Holders API Documentation",
    description="Documentation for the Chainbase Token Top Holders API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "token", "holders"}
)
def get_token_top_holders_docs():
    """Returns documentation for the Token Top Holders API endpoint."""
    return """
    # Token Top Holders API
    
    Get the list of top holders of the specified contract.
    
    ## Endpoint
    
    `GET /v1/token/top-holders`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `contract_address` (required): The address of the token contract
    - `page` (optional): The page offset, default is 1
    - `limit` (optional): The desired page size limit. Less or equal than 100, default is 20
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": [
        {
          "address": "0x...",
          "balance": "1000000000000000000000",
          "percentage": "10.5"
        }
      ],
      "next_page": 2,
      "count": 100
    }
    ```
    """

@mcp.resource(
    uri="doc://chainbase/token-holders",
    name="Token Holders API Documentation",
    description="Documentation for the Chainbase Token Holders API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "token", "holders"}
)
def get_token_holders_docs():
    """Returns documentation for the Token Holders API endpoint."""
    return """
    # Token Holders API
    
    Get the list of holders of the specified contract.
    
    ## Endpoint
    
    `GET /v1/token/holders`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `contract_address` (required): The address of the token contract
    - `page` (optional): The page offset, default is 1
    - `limit` (optional): The desired page size limit. Less or equal than 100, default is 20
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": [
        "0x...", "0x...", "0x..."
      ],
      "next_page": 2,
      "count": 100
    }
    ```
    """

@mcp.resource(
    uri="doc://chainbase/token-price",
    name="Token Price API Documentation",
    description="Documentation for the Chainbase Token Price API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "token", "price"}
)
def get_token_price_docs():
    """Returns documentation for the Token Price API endpoint."""
    return """
    # Token Price API
    
    Get the price of the specified token.
    
    ## Endpoint
    
    `GET /v1/token/price`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `contract_address` (required): The address of the token contract
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": {
        "usd": "1.23",
        "usd_24h_change": "2.34",
        "usd_24h_vol": "1000000",
        "last_updated_at": 1629781234
      }
    }
    ```
    """

@mcp.resource(
    uri="doc://chainbase/token-price-history",
    name="Token Price History API Documentation",
    description="Documentation for the Chainbase Token Price History API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "token", "price", "history"}
)
def get_token_price_history_docs():
    """Returns documentation for the Token Price History API endpoint."""
    return """
    # Token Price History API
    
    Get the historical price of the specified token.
    
    ## Endpoint
    
    `GET /v1/token/price/history`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `contract_address` (required): The address of the token contract
    - `from_timestamp` (required): Inclusive start timestamp
    - `end_timestamp` (required): Inclusive end timestamp, the interval should not exceed 90 days
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": [
        {
          "timestamp": 1629700000,
          "usd": "1.23",
          "usd_24h_change": "2.34",
          "usd_24h_vol": "1000000"
        },
        {
          "timestamp": 1629786400,
          "usd": "1.24",
          "usd_24h_change": "0.81",
          "usd_24h_vol": "1100000"
        }
      ]
    }
    ```
    
    Note: The interval between from_timestamp and end_timestamp should not exceed 90 days.
    """

@mcp.resource(
    uri="doc://chainbase/token-transfers",
    name="Token Transfers API Documentation",
    description="Documentation for the Chainbase Token Transfers API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "token", "transfers", "transactions"}
)
def get_token_transfers_docs():
    """Returns documentation for the Token Transfers API endpoint."""
    return """
    # Token Transfers API
    
    Retrieves historical token transfer transactions for any ERC20 contract.
    
    ## Endpoint
    
    `GET /v1/token/transfers`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `contract_address` (optional): The address of the token contract
    - `address` (optional): A hex string referencing a wallet address
    - `from_block` (optional): Inclusive from block number (hex string or int)
    - `to_block` (optional): Inclusive to block number (hex string, int, or 'latest')
    - `from_timestamp` (optional): Inclusive start timestamp
    - `end_timestamp` (optional): Inclusive end timestamp
    - `page` (optional): The page offset, default is 1
    - `limit` (optional): The desired page size limit. Less or equal than 100, default is 20
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": [
        {
          "block_hash": "0x...",
          "block_number": "12345678",
          "block_timestamp": 1629700000,
          "transaction_hash": "0x...",
          "transaction_index": "10",
          "log_index": "5",
          "from_address": "0x...",
          "to_address": "0x...",
          "value": "1000000000000000000",
          "contract_address": "0x..."
        }
      ],
      "next_page": 2,
      "count": 100
    }
    ```
    """

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
