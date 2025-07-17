from fastmcp import FastMCP
from .http_client import the_graph_token_api_client
from .utils import normalize_ethereum_contract_address

mcp = FastMCP("TheGraphTokenApiTokenHolders")

@mcp.tool()
async def token_holders(address: str, network_id: str = "mainnet", order_direction: str = "desc"):
    """
    Get the holders of an ERC-20 token contract address.
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    order_direction: asc, desc
    {
      "data": [
        {
          "block_num": 22578579,
          "last_balance_update": "2025-05-28 03:25:47",
          "address": "0x36aff7001294dae4c2ed4fdefc478a00de77f090",
          "amount": "2868440291872963359806035918",
          "value": 2868440291.8729634,
          "decimals": 18,
          "symbol": "GRT",
          "network_id": "mainnet"
        }
      ]
    }
    """
    address = normalize_ethereum_contract_address(address)
    resp = await the_graph_token_api_client.get(f"/holders/evm/{address}?network_id={network_id}?orderDirection={order_direction}")
    resp = resp.json()
    return resp