# https://mainnet.auto-drive.autonomys.xyz/api/docs
from fastmcp import FastMCP
from spoon_ai.tools.the_graph_token_api.balances_by_address import mcp as balances_by_address_server
from spoon_ai.tools.the_graph_token_api.historical_balances import mcp as historical_balances_server
from spoon_ai.tools.the_graph_token_api.nft import mcp as nft_server
from spoon_ai.tools.the_graph_token_api.ohlcv import mcp as ohlcv_server
from spoon_ai.tools.the_graph_token_api.swap_events import mcp as swap_events_server
from spoon_ai.tools.the_graph_token_api.token_holders import mcp as token_holders_server
from spoon_ai.tools.the_graph_token_api.token_metadata import mcp as token_metadata_server
from spoon_ai.tools.the_graph_token_api.transfer_events import mcp as transfer_events_server

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