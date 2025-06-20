from fastmcp import FastMCP
from spoon_ai.tools.the_graph_token_api.http_client import the_graph_token_api_client
from spoon_ai.tools.the_graph_token_api.utils import normalize_ethereum_contract_address

mcp = FastMCP("TheGraphTokenApiTokenMetadata")

@mcp.tool()
async def token_holders(address: str, network_id: str = "mainnet"):
    """
    Get the metadata of an ERC-20 token contract address.
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    {
      "data": [
        {
          "block_num": 22589353,
          "datetime": "2025-05-29 15:40:11",
          "address": "0xc944e90c64b2c07662a292be6244bdf05cda44a7",
          "decimals": 18,
          "symbol": "GRT",
          "name": "Graph Token",
          "circulating_supply": "16667753581.233711",
          "holders": 139562,
          "network_id": "mainnet",
          "icon": {
            "web3icon": "GRT"
          }
        }
      ]
    }
    """
    address = normalize_ethereum_contract_address(address)
    resp = await the_graph_token_api_client.get(f"/holders/evm/{address}?network_id={network_id}")
    resp = resp.json()
    return resp