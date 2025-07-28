from fastmcp import FastMCP
from .http_client import the_graph_token_api_client
from .utils import normalize_ethereum_contract_address

mcp = FastMCP("TheGraphTokenApiBalancesByAddress")

@mcp.tool()
async def balances_by_address(address: str, network_id: str = "mainnet", contract: str = ''):
    """
    Get the ERC-20 and native ether balances of an address. Can be restricted to a certain token contract address
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    {
      "data": [
        {
          "block_num": 22586773,
          "datetime": "2025-05-29 06:58:47",
          "contract": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
          "amount": "237637742936991878321",
          "value": 237.63774293699188,
          "decimals": 18,
          "symbol": "ETH",
          "network_id": "mainnet"
        }
      ]
    }
    """
    address = normalize_ethereum_contract_address(address)
    url = f"/balances/evm/{address}?network={network_id}"
    if contract:
        url += f"&contract={contract}"
    resp = await the_graph_token_api_client.get(url)
    resp = resp.json()
    return resp