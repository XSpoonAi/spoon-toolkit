from fastmcp import FastMCP
from .http_client import the_graph_token_api_client
from .utils import normalize_ethereum_contract_address

mcp = FastMCP("TheGraphTokenApiTransferEvents")

@mcp.tool()
async def transfer_events(
    network_id: str = 'mainnet', from_address: str = '', to_address: str = '', contract_address: str = '',
    start_timestamp_seconds: int = 0, end_timestamp_seconds: int = 1750388066_00
):
    """
    Get ERC-20 and native transfer events on a certain blockchain network.
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    mainnet means Ethereum mainnet
    {
      "data": [
        {
          "block_num": 22349873,
          "datetime": "2025-04-26 01:18:47",
          "timestamp": 1745630327,
          "transaction_id": "0xd80ed9764b0bc25b982668f66ec1cf46dbe27bcd01dffcd487f43c92f72b2a84",
          "contract": "0xc944e90c64b2c07662a292be6244bdf05cda44a7",
          "from": "0x7d2fbc0eefdb8721b27d216469e79ef288910a83",
          "to": "0xa5eb953d1ce9d6a99893cbf6d83d8abcca9b8804",
          "decimals": 18,
          "symbol": "GRT",
          "value": 11068.393958659999
        }
      ]
    }
    """
    url = "/transfers/evm"
    query_params = {
        "network_id": network_id,
        "from": normalize_ethereum_contract_address(from_address),
        "to": normalize_ethereum_contract_address(to_address),
        "contract": normalize_ethereum_contract_address(contract_address),
        "startTime": str(start_timestamp_seconds),
        "endTime": str(end_timestamp_seconds),
        "orderBy": "timestamp",
        "orderDirection": "desc",  # asc
        # "transaction_id": "",
        # "limit": 10,
        "page": "1",
    }
    query_params = {k: v for k, v in query_params.items() if v}
    if len(query_params) > 0:
        url += "?"
    for k, v in query_params:
        url += f"&{k}={v}"
    resp = await the_graph_token_api_client.get(url)
    resp = resp.json()
    return resp