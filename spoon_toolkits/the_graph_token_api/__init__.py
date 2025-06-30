# https://thegraph.com/docs/en/token-api/evm/get-balances-evm-by-address/
from fastmcp import FastMCP
from .balances_by_address import mcp as balances_by_address_server
from .historical_balances import mcp as historical_balances_server
from .nft import mcp as nft_server
from .ohlcv import mcp as ohlcv_server
from .swap_events import mcp as swap_events_server
from .token_holders import mcp as token_holders_server
from .token_metadata import mcp as token_metadata_server
from .transfer_events import mcp as transfer_events_server

mcp_server = FastMCP("TheGraphTokenApiServer")
mcp_server.mount("BalancesByAddress", balances_by_address_server)
mcp_server.mount("HistoricalBalances", historical_balances_server)
mcp_server.mount("Nft", nft_server)
mcp_server.mount("Ohlcv", ohlcv_server)
mcp_server.mount("SwapEvents", swap_events_server)
mcp_server.mount("TokenHolders", token_holders_server)
mcp_server.mount("TokenMetadata", token_metadata_server)
mcp_server.mount("TransferEvents", transfer_events_server)

if __name__ == "__main__":
    # mcp_server.run(host='0.0.0.0', port=8000)
    mcp_server.run()