"""Deribit API integration toolkit for SpoonAI"""

from fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("Deribit Tools")

# Import core components
from .jsonrpc_client import DeribitJsonRpcClient, DeribitJsonRpcError
from .auth import DeribitAuth, DeribitAuthError
from .base import DeribitBaseTool
from .env import DeribitConfig

# Import tools
from .market_data import (
    GetInstrumentsTool,
    GetOrderBookTool,
    GetTickerTool,
    GetLastTradesTool,
    GetIndexPriceTool,
    GetBookSummaryTool
)
from .account import (
    GetAccountSummaryTool,
    GetPositionsTool,
    GetOrderHistoryTool,
    GetTradeHistoryTool
)
from .trading import (
    PlaceBuyOrderTool,
    PlaceSellOrderTool,
    CancelOrderTool,
    CancelAllOrdersTool,
    GetOpenOrdersTool,
    EditOrderTool
)

# Register tools with MCP server
@mcp.tool()
async def get_instruments(currency: str, kind: str = "any", expired: bool = False):
    """Get list of available instruments on Deribit"""
    tool = GetInstrumentsTool()
    result = await tool.execute(currency=currency, kind=kind, expired=expired)
    return result

@mcp.tool()
async def get_order_book(instrument_name: str, depth: int = 20):
    """Get order book for a specific instrument"""
    tool = GetOrderBookTool()
    result = await tool.execute(instrument_name=instrument_name, depth=depth)
    return result

@mcp.tool()
async def get_account_summary(currency: str, extended: bool = False):
    """Get account summary (requires authentication)"""
    tool = GetAccountSummaryTool()
    result = await tool.execute(currency=currency, extended=extended)
    return result

@mcp.tool()
async def get_positions(currency: str, kind: str = "any"):
    """Get current positions (requires authentication)"""
    tool = GetPositionsTool()
    result = await tool.execute(currency=currency, kind=kind)
    return result

@mcp.tool()
async def get_ticker(instrument_name: str):
    """Get ticker data for a specific instrument"""
    tool = GetTickerTool()
    result = await tool.execute(instrument_name=instrument_name)
    return result

@mcp.tool()
async def get_last_trades(instrument_name: str, count: int = 10, include_old: bool = False, sorting: str = "desc"):
    """Get last trades for a specific instrument"""
    tool = GetLastTradesTool()
    result = await tool.execute(
        instrument_name=instrument_name,
        count=count,
        include_old=include_old,
        sorting=sorting
    )
    return result

@mcp.tool()
async def get_index_price(index_name: str):
    """Get index price for a currency"""
    tool = GetIndexPriceTool()
    result = await tool.execute(index_name=index_name)
    return result

@mcp.tool()
async def get_book_summary(currency: str, kind: str = "any"):
    """Get book summary by currency"""
    tool = GetBookSummaryTool()
    result = await tool.execute(currency=currency, kind=kind)
    return result

@mcp.tool()
async def place_buy_order(
    instrument_name: str,
    amount: float,
    price: float = None,
    order_type: str = "limit",
    time_in_force: str = "good_til_cancelled",
    reduce_only: bool = False,
    post_only: bool = False
):
    """Place a buy order (requires authentication)"""
    tool = PlaceBuyOrderTool()
    result = await tool.execute(
        instrument_name=instrument_name,
        amount=amount,
        price=price,
        order_type=order_type,
        time_in_force=time_in_force,
        reduce_only=reduce_only,
        post_only=post_only
    )
    return result

@mcp.tool()
async def place_sell_order(
    instrument_name: str,
    amount: float,
    price: float = None,
    order_type: str = "limit",
    time_in_force: str = "good_til_cancelled",
    reduce_only: bool = False,
    post_only: bool = False
):
    """Place a sell order (requires authentication)"""
    tool = PlaceSellOrderTool()
    result = await tool.execute(
        instrument_name=instrument_name,
        amount=amount,
        price=price,
        order_type=order_type,
        time_in_force=time_in_force,
        reduce_only=reduce_only,
        post_only=post_only
    )
    return result

@mcp.tool()
async def cancel_order(order_id: str):
    """Cancel an order by order ID (requires authentication)"""
    tool = CancelOrderTool()
    result = await tool.execute(order_id=order_id)
    return result

@mcp.tool()
async def cancel_all_orders(currency: str, kind: str = "any", type: str = "all"):
    """Cancel all orders for a currency (requires authentication)"""
    tool = CancelAllOrdersTool()
    result = await tool.execute(currency=currency, kind=kind, type=type)
    return result

@mcp.tool()
async def get_open_orders(instrument_name: str):
    """Get open orders for an instrument (requires authentication)"""
    tool = GetOpenOrdersTool()
    result = await tool.execute(instrument_name=instrument_name)
    return result

@mcp.tool()
async def edit_order(order_id: str, amount: float = None, price: float = None):
    """Edit an existing order (requires authentication)"""
    tool = EditOrderTool()
    result = await tool.execute(order_id=order_id, amount=amount, price=price)
    return result

@mcp.tool()
async def get_order_history(instrument_name: str, count: int = 20, offset: int = 0):
    """Get order history for an instrument (requires authentication)"""
    tool = GetOrderHistoryTool()
    result = await tool.execute(
        instrument_name=instrument_name,
        count=count,
        offset=offset
    )
    return result

@mcp.tool()
async def get_trade_history(instrument_name: str, count: int = 20, offset: int = 0):
    """Get trade history for an instrument (requires authentication)"""
    tool = GetTradeHistoryTool()
    result = await tool.execute(
        instrument_name=instrument_name,
        count=count,
        offset=offset
    )
    return result

# Export
__all__ = [
    "mcp",
    "DeribitJsonRpcClient",
    "DeribitJsonRpcError",
    "DeribitAuth",
    "DeribitAuthError",
    "DeribitBaseTool",
    "DeribitConfig",
    "GetInstrumentsTool",
    "GetOrderBookTool",
    "GetTickerTool",
    "GetLastTradesTool",
    "GetIndexPriceTool",
    "GetBookSummaryTool",
    "GetAccountSummaryTool",
    "GetPositionsTool",
    "GetOrderHistoryTool",
    "GetTradeHistoryTool",
    "PlaceBuyOrderTool",
    "PlaceSellOrderTool",
    "CancelOrderTool",
    "CancelAllOrdersTool",
    "GetOpenOrdersTool",
    "EditOrderTool",
]

