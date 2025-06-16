# https://docs.chainbase.com/api-reference/overview
import os
from fastmcp import FastMCP
import dotenv
dotenv.load_dotenv()

# Import all module servers
from balance import mcp as balance_server
from basic import mcp as basic_server
from token_api import mcp as token_api_server

# Import tool classes
from chainbase_tools import (
    GetLatestBlockNumberTool,
    GetBlockByNumberTool,
    GetTransactionByHashTool,
    GetAccountTransactionsTool,
    ContractCallTool,
    GetAccountTokensTool,
    GetAccountNFTsTool,
    GetAccountBalanceTool,
    GetTokenMetadataTool
)

# Create main server
mcp_server = FastMCP(name="ChainbaseToolsServer")

# Mount all module servers
mcp_server.mount("Balance", balance_server)
mcp_server.mount("Basic", basic_server)
mcp_server.mount("TokenAPI", token_api_server)

# Export the main server and tool classes
__all__ = [
    "mcp_server",
    "GetLatestBlockNumberTool",
    "GetBlockByNumberTool",
    "GetTransactionByHashTool",
    "GetAccountTransactionsTool",
    "ContractCallTool",
    "GetAccountTokensTool",
    "GetAccountNFTsTool",
    "GetAccountBalanceTool",
    "GetTokenMetadataTool"
]

# Add main block for direct execution
if __name__ == "__main__":
    # Default API key if not provided in environment
    if not os.environ.get("CHAINBASE_API_KEY"):
        raise ValueError("CHAINBASE_API_KEY is not set")

    
    # Get configuration from environment variables with defaults
    host = os.environ.get("CHAINBASE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHAINBASE_PORT", "8000"))
    path = os.environ.get("CHAINBASE_PATH", "/sse")

    # Start FastMCP server with SSE transport protocol
    mcp_server.run(
        transport="sse",
        host=host,
        port=port,
        path=path
    )