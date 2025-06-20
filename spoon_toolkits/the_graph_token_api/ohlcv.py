from fastmcp import FastMCP
from spoon_ai.tools.the_graph_token_api.http_client import the_graph_token_api_client
from spoon_ai.tools.the_graph_token_api.utils import normalize_ethereum_contract_address

mcp = FastMCP("TheGraphTokenApiOhlcv")

@mcp.tool()
async def ohlcv_by_contract(address: str, network_id: str = "mainnet"):
    """
    Get the Open/High/Low/Close/Volume pricing data of an ERC-20 token contract address.
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    {
      "data": [
        {
          "datetime": "2025-05-29 15:00:00",
          "ticker": "WETHUSD",
          "open": 2669.130852861705,
          "high": 2669.130852861705,
          "low": 2669.130852861705,
          "close": 2669.130852861705,
          "volume": 184897.1695477702,
          "uaw": 31,
          "transactions": 35
        }
      ]
    }
    """
    address = normalize_ethereum_contract_address(address)
    resp = await the_graph_token_api_client.get(f"/ohlc/prices/evm/{address}?network_id={network_id}")
    resp = resp.json()
    return resp

@mcp.tool()
async def ohlcv_by_pool(address: str, network_id: str = "mainnet"):
    """
    Get the Open/High/Low/Close/Volume pricing data of a Uniswap v2 or v3 liquidity pool contract address.
    Get the liquidity pool address by calling the liquidity_pools function
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    {
      "data": [
        {
          "datetime": "2025-05-29 15:00:00",
          "ticker": "WETHUSDC",
          "open": 2674.206768283323,
          "high": 2674.206768283323,
          "low": 2648.1288363948797,
          "close": 2648.1288363948797,
          "volume": 5062048.294222999,
          "transactions": 169
        }
      ]
    }
    """
    address = normalize_ethereum_contract_address(address)
    resp = await the_graph_token_api_client.get(f"/ohlc/pools/evm/{address}?network_id={network_id}")
    resp = resp.json()
    return resp

@mcp.tool()
async def liquidity_pools(network_id: str = "mainnet"):
    """
    Get the contract addresses of Uniswap v2 and v3 liquidity pools.
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    {
      "data": [
        {
          "block_num": 22589384,
          "datetime": "2025-05-29 15:46:23",
          "transaction_id": "0x43cee95f1449b6b4d394fab31234fd6decdcd049153cc1338fe627e5483a3d36",
          "factory": "0x000000000004444c5dc75cb358380d2e3de08a90",
          "pool": "0x12b900f4e5c4b1d2aab6870220345c668b068fc6e588dd59dfe6f223d60608f1",
          "token0": {
            "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "symbol": "USDT",
            "decimals": 6
          },
          "token1": {
            "address": "0xf2c88757f8d03634671208935974b60a2a28bdb3",
            "symbol": "SHELL",
            "decimals": 18
          },
          "fee": 699000,
          "protocol": "uniswap_v4",
          "network_id": "mainnet"
        }
      ]
    }
    """
    resp = await the_graph_token_api_client.get(f"/pools/evm?network_id={network_id}")
    resp = resp.json()
    return resp