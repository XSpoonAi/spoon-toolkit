import os
import traceback
from typing import List, Optional

import requests
from fastmcp import FastMCP, Context
from fastmcp.resources import TextResource

# Get API key from environment variable
api_key = os.getenv("CHAINBASE_API_KEY", "")
base_url = "https://api.chainbase.online/v1"
mcp = FastMCP(name="ChainbaseBalanceServer")

@mcp.tool()
async def get_account_tokens(ctx: Context = None, chain_id: int = 1, address: str = None, 
                            contract_address: Optional[str] = None, 
                            limit: int = 20, page: int = 1):
    """Retrieve all token balances for all ERC20 tokens for a specified address.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        address[Required][str]: A hex string referencing a wallet address
        contract_address[Optional][str]: The address of the token contract, or filter multiple addresses (max 100)
        limit[Optional][int]: The desired page size limit. Less or equal than 100, default is 20
        page[Optional][int]: The page offset, default is 1
    returns:
        tokens: dict containing token balances information
    """
    try:
        url = f"{base_url}/account/tokens"
        headers = {"x-api-key": api_key}
        
        # Build query parameters
        querystring = {
            "chain_id": int(chain_id), 
            "address": address,
            "limit": min(limit, 100),  # Ensure not exceeding API limit
            "page": max(page, 1)       # Ensure page number is at least 1
        }
        
        # Add optional parameters
        if contract_address:
            querystring["contract_address"] = contract_address
            
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting account tokens: {e}")
        ctx.log.error(traceback.format_exc())
        return None

@mcp.tool()
async def get_account_nfts(ctx: Context = None, chain_id: int = 1, address: str = None,
                          contract_address: Optional[str] = None,
                          page: int = 1, limit: int = 20):
    """Get the list of NFTs owned by an account.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        address[Required][str]: A hex string referencing a wallet address
        contract_address[Optional][str]: The address of the NFT contract, or filter multiple addresses (max 100)
        page[Optional][int]: The page offset, default is 1
        limit[Optional][int]: The desired page size limit. Less or equal than 100, default is 20
    returns:
        nfts: dict containing NFT information owned by the address
    """
    try:
        url = f"{base_url}/account/nfts"
        headers = {"x-api-key": api_key}
        
        # Build query parameters
        querystring = {
            "chain_id": int(chain_id),
            "address": address,
            "page": max(page, 1),       # Ensure page number is at least 1
            "limit": min(limit, 100)    # Ensure not exceeding API limit
        }
        
        # Add optional parameters
        if contract_address:
            querystring["contract_address"] = contract_address
            
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting account NFTs: {e}")
        ctx.log.error(traceback.format_exc())
        return None

@mcp.tool()
async def get_account_balance(ctx: Context = None, chain_id: int = 1, address: str = None,
                             to_block: Optional[str] = None):
    """Returns the native token balance for a specified address.
    args:
        ctx: Context - MCP context object for logging and progress tracking
        chain_id[Required][int]: chain network id, e.g. 1 for Ethereum, 137 for Polygon, etc.
        address[Required][str]: A hex string referencing a wallet address
        to_block[Optional][str]: block decimal number, hex number or 'latest'
    returns:
        balance: dict containing the native token balance information
    """
    try:
        url = f"{base_url}/account/balance"
        headers = {"x-api-key": api_key}
        
        # Build query parameters
        querystring = {
            "chain_id": int(chain_id),
            "address": address
        }
        
        # Add optional parameters
        if to_block:
            querystring["to_block"] = to_block
            
        response = requests.request("GET", url, headers=headers, params=querystring)
        return response.json()
    except Exception as e:
        ctx.log.error(f"Error getting account native balance: {e}")
        ctx.log.error(traceback.format_exc())
        return None

@mcp.resource(
    uri="doc://chainbase/account-tokens",
    name="Account Tokens API Documentation",
    description="Documentation for the Chainbase Account Tokens API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "tokens", "ERC20"}
)
def get_account_tokens_docs():
    """Returns documentation for the Account Tokens API endpoint."""
    return """
    # Account Tokens API
    
    Retrieve all token balances for all ERC20 tokens for a specified address.
    
    By default, it will return all token balances for all ERC20 tokens that the address has ever received. 
    You can specify a contract address to check the balance of a non-standard contract.
    
    ## Endpoint
    
    `GET /v1/account/tokens`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `address` (required): A hex string referencing a wallet address
    - `contract_address` (optional): The address of the token contract, or filter multiple addresses (max 100)
    - `limit` (optional): The desired page size limit. Less or equal than 100, default is 20
    - `page` (optional): The page offset, default is 1
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": [
        {
          // Token metadata and balance information
        }
      ],
      "next_page": 2,
      "count": 100
    }
    ```
    """

@mcp.resource(
    uri="doc://chainbase/account-nfts",
    name="Account NFTs API Documentation",
    description="Documentation for the Chainbase Account NFTs API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "nfts", "NFT"}
)
def get_account_nfts_docs():
    """Returns documentation for the Account NFTs API endpoint."""
    return """
    # Account NFTs API
    
    Get the list of NFTs owned by an account.
    
    ## Endpoint
    
    `GET /v1/account/nfts`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `address` (required): A hex string referencing a wallet address
    - `contract_address` (optional): The address of the NFT contract, or filter multiple addresses (max 100)
    - `page` (optional): The page offset, default is 1
    - `limit` (optional): The desired page size limit. Less or equal than 100, default is 20
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": [
        {
          // NFT metadata and ownership information
        }
      ],
      "next_page": 2,
      "count": 100
    }
    ```
    """

@mcp.resource(
    uri="doc://chainbase/account-balance",
    name="Account Native Balance API Documentation",
    description="Documentation for the Chainbase Account Native Balance API endpoint",
    mime_type="text/markdown",
    tags={"blockchain", "chainbase", "balance", "native token"}
)
def get_account_balance_docs():
    """Returns documentation for the Account Native Balance API endpoint."""
    return """
    # Account Native Balance API
    
    Returns the native token balance for a specified address.
    
    ## Endpoint
    
    `GET /v1/account/balance`
    
    ## Parameters
    
    - `chain_id` (required): Chain network ID
    - `address` (required): A hex string referencing a wallet address
    - `to_block` (optional): Block decimal number, hex number or 'latest'
    
    ## Response Structure
    
    ```json
    {
      "code": 0,
      "message": "ok",
      "data": "1234567890" // Balance as a string
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