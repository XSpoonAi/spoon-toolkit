from fastmcp import FastMCP
from .http_client import the_graph_token_api_client
from .utils import normalize_ethereum_contract_address

mcp = FastMCP("TheGraphTokenApiHistoricalBalances")

@mcp.tool()
async def historical_balances(address: str):
    """
    Get the historical ERC-20 and native ether balances of an address.
    """
    address = normalize_ethereum_contract_address(address)
    resp = await the_graph_token_api_client.get(f"/historical/balances/evm/{address}")
    resp = resp.json()
    return resp