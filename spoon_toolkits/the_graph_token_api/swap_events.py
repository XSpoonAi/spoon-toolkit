from fastmcp import FastMCP
from spoon_ai.tools.the_graph_token_api.http_client import the_graph_token_api_client
from spoon_ai.tools.the_graph_token_api.utils import normalize_ethereum_contract_address

mcp = FastMCP("TheGraphTokenApiSwapEvents")

@mcp.tool()
async def swap_events(
    network_id: str = 'mainnet', pool_address: str = '',
    caller_address: str = '', sender_address: str = '', recipient_address: str = '',
    start_timestamp_seconds: int = 0, end_timestamp_seconds: int = 1750388066_00
):
    """
    Get Uniswap v2 and v3 swap events.
    If you need to filter by a swap pool, get the pool address with the function liquidity_pools.
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    mainnet means Ethereum mainnet
    {
      "data": [
        {
          "block_num": 22589391,
          "datetime": "2025-05-29 15:47:47",
          "timestamp": 1748533667,
          "transaction_id": "0x1ce019b0ad129b8bd21b6c83b75de5e5fd7cd07f2ee739ca3198adcbeb61f5a9",
          "caller": "0x66a9893cc07d91d95644aedd05d03f95e1dba8af",
          "pool": "0xb98437c7ba28c6590dd4e1cc46aa89eed181f97108e5b6221730d41347bc817f",
          "factory": "0x000000000004444c5dc75cb358380d2e3de08a90",
          "token0": {
            "address": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
            "symbol": "WBTC",
            "decimals": 8
          },
          "token1": {
            "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "symbol": "USDC",
            "decimals": 6
          },
          "sender": "0x66a9893cc07d91d95644aedd05d03f95e1dba8af",
          "recipient": null,
          "amount0": "-894320",
          "amount1": "957798098",
          "value0": -0.0089432,
          "value1": 957.798098,
          "price0": 107417.48517180652,
          "price1": 0.00000930947134352077,
          "protocol": "uniswap_v4",
          "network_id": "mainnet"
        }
      ]
    }
    """
    url = "/swaps/evm"
    query_params = {
        "network_id": network_id,
        "pool": normalize_ethereum_contract_address(pool_address),
        "caller": normalize_ethereum_contract_address(caller_address),
        "sender": normalize_ethereum_contract_address(sender_address),
        "recipient": normalize_ethereum_contract_address(recipient_address),
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