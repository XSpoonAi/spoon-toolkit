"""Market data tools for Deribit API (Public methods)"""

import logging
from typing import Any, Dict, Optional
from pydantic import Field

from .base import DeribitBaseTool, ToolResult

logger = logging.getLogger(__name__)


class GetInstrumentsTool(DeribitBaseTool):
    """Get list of available instruments on Deribit"""
    
    name: str = "deribit_get_instruments"
    description: str = (
        "Get list of available instruments (futures, options, spot) on Deribit. "
        "Returns instrument details including name, currency, kind, expiration, etc."
    )
    
    parameters: dict = {
        "type": "object",
        "properties": {
            "currency": {
                "type": "string",
                "enum": ["BTC", "ETH", "USDC"],
                "description": "Currency code (BTC, ETH, or USDC)"
            },
            "kind": {
                "type": "string",
                "enum": ["future", "option", "spot", "any"],
                "default": "any",
                "description": "Instrument kind filter"
            },
            "expired": {
                "type": "boolean",
                "default": False,
                "description": "Include expired instruments"
            }
        },
        "required": ["currency"]
    }
    
    currency: Optional[str] = Field(default=None, description="Currency code")
    kind: str = Field(default="any", description="Instrument kind")
    expired: bool = Field(default=False, description="Include expired instruments")
    
    async def execute(self, **kwargs) -> ToolResult:
        """Execute get instruments tool"""
        try:
            currency = kwargs.get("currency", self.currency)
            kind = kwargs.get("kind", self.kind)
            expired = kwargs.get("expired", self.expired)
            
            if not currency:
                return ToolResult(error="Parameter 'currency' is required")
            
            params = {
                "currency": currency,
                "kind": kind if kind != "any" else None,
                "expired": expired
            }
            
            # Remove None values
            params = {k: v for k, v in params.items() if v is not None}
            
            result = await self._call_public_method("public/get_instruments", params)
            
            return ToolResult(output=result)
            
        except Exception as e:
            logger.error(f"Error in GetInstrumentsTool: {e}")
            return ToolResult(error=f"Failed to get instruments: {str(e)}")


class GetOrderBookTool(DeribitBaseTool):
    """Get order book for a specific instrument"""
    
    name: str = "deribit_get_order_book"
    description: str = (
        "Get order book (bids and asks) for a specific instrument. "
        "Returns current market depth with price and size information."
    )
    
    parameters: dict = {
        "type": "object",
        "properties": {
            "instrument_name": {
                "type": "string",
                "description": "Instrument name (e.g., 'BTC-PERPETUAL', 'BTC-25JAN25-50000-C')"
            },
            "depth": {
                "type": "integer",
                "default": 20,
                "description": "Number of price levels to return (1-2500)"
            }
        },
        "required": ["instrument_name"]
    }
    
    instrument_name: Optional[str] = Field(default=None, description="Instrument name")
    depth: int = Field(default=20, description="Order book depth")
    
    async def execute(self, **kwargs) -> ToolResult:
        """Execute get order book tool"""
        try:
            instrument_name = kwargs.get("instrument_name", self.instrument_name)
            depth = kwargs.get("depth", self.depth)
            
            if not instrument_name:
                return ToolResult(error="Parameter 'instrument_name' is required")
            
            params = {
                "instrument_name": instrument_name,
                "depth": depth
            }
            
            result = await self._call_public_method("public/get_order_book", params)
            
            return ToolResult(output=result)
            
        except Exception as e:
            logger.error(f"Error in GetOrderBookTool: {e}")
            return ToolResult(error=f"Failed to get order book: {str(e)}")


class GetTickerTool(DeribitBaseTool):
    """Get ticker data for a specific instrument"""
    
    name: str = "deribit_get_ticker"
    description: str = (
        "Get ticker data for a specific instrument. "
        "Returns current price, 24h statistics, volume, open interest, etc."
    )
    
    parameters: dict = {
        "type": "object",
        "properties": {
            "instrument_name": {
                "type": "string",
                "description": "Instrument name (e.g., 'BTC-PERPETUAL', 'BTC-25JAN25-50000-C')"
            }
        },
        "required": ["instrument_name"]
    }
    
    instrument_name: Optional[str] = Field(default=None, description="Instrument name")
    
    async def execute(self, **kwargs) -> ToolResult:
        """Execute get ticker tool"""
        try:
            instrument_name = kwargs.get("instrument_name", self.instrument_name)
            
            if not instrument_name:
                return ToolResult(error="Parameter 'instrument_name' is required")
            
            params = {
                "instrument_name": instrument_name
            }
            
            result = await self._call_public_method("public/ticker", params)
            
            return ToolResult(output=result)
            
        except Exception as e:
            logger.error(f"Error in GetTickerTool: {e}")
            return ToolResult(error=f"Failed to get ticker: {str(e)}")


class GetLastTradesTool(DeribitBaseTool):
    """Get last trades for a specific instrument"""
    
    name: str = "deribit_get_last_trades"
    description: str = (
        "Get last trades (recent transactions) for a specific instrument. "
        "Returns trade history with price, amount, direction, timestamp, etc."
    )
    
    parameters: dict = {
        "type": "object",
        "properties": {
            "instrument_name": {
                "type": "string",
                "description": "Instrument name (e.g., 'BTC-PERPETUAL', 'BTC-25JAN25-50000-C')"
            },
            "count": {
                "type": "integer",
                "default": 10,
                "description": "Number of trades to return (1-1000)"
            },
            "include_old": {
                "type": "boolean",
                "default": False,
                "description": "Include older trades"
            },
            "sorting": {
                "type": "string",
                "enum": ["asc", "desc"],
                "default": "desc",
                "description": "Sort order: 'asc' for ascending, 'desc' for descending"
            }
        },
        "required": ["instrument_name"]
    }
    
    instrument_name: Optional[str] = Field(default=None, description="Instrument name")
    count: int = Field(default=10, description="Number of trades")
    include_old: bool = Field(default=False, description="Include old trades")
    sorting: str = Field(default="desc", description="Sort order")
    
    async def execute(self, **kwargs) -> ToolResult:
        """Execute get last trades tool"""
        try:
            instrument_name = kwargs.get("instrument_name", self.instrument_name)
            count = kwargs.get("count", self.count)
            include_old = kwargs.get("include_old", self.include_old)
            sorting = kwargs.get("sorting", self.sorting)
            
            if not instrument_name:
                return ToolResult(error="Parameter 'instrument_name' is required")
            
            # Validate count
            if count < 1 or count > 1000:
                return ToolResult(error="Parameter 'count' must be between 1 and 1000")
            
            params = {
                "instrument_name": instrument_name,
                "count": count,
                "include_old": include_old,
                "sorting": sorting
            }
            
            result = await self._call_public_method("public/get_last_trades_by_instrument", params)
            
            return ToolResult(output=result)
            
        except Exception as e:
            logger.error(f"Error in GetLastTradesTool: {e}")
            return ToolResult(error=f"Failed to get last trades: {str(e)}")


class GetIndexPriceTool(DeribitBaseTool):
    """Get index price for a currency"""
    
    name: str = "deribit_get_index_price"
    description: str = (
        "Get index price for a specific currency. "
        "Returns the current index price used for margin calculations."
    )
    
    parameters: dict = {
        "type": "object",
        "properties": {
            "index_name": {
                "type": "string",
                "description": "Index name (e.g., 'btc_usd', 'eth_usd')"
            }
        },
        "required": ["index_name"]
    }
    
    index_name: Optional[str] = Field(default=None, description="Index name")
    
    async def execute(self, **kwargs) -> ToolResult:
        """Execute get index price tool"""
        try:
            index_name = kwargs.get("index_name", self.index_name)
            
            if not index_name:
                return ToolResult(error="Parameter 'index_name' is required")
            
            params = {
                "index_name": index_name
            }
            
            result = await self._call_public_method("public/get_index_price", params)
            
            return ToolResult(output=result)
            
        except Exception as e:
            logger.error(f"Error in GetIndexPriceTool: {e}")
            return ToolResult(error=f"Failed to get index price: {str(e)}")


class GetBookSummaryTool(DeribitBaseTool):
    """Get book summary by currency"""
    
    name: str = "deribit_get_book_summary"
    description: str = (
        "Get book summary for all instruments of a specific currency and kind. "
        "Returns summary information including best bid/ask, volume, open interest, etc."
    )
    
    parameters: dict = {
        "type": "object",
        "properties": {
            "currency": {
                "type": "string",
                "enum": ["BTC", "ETH", "USDC"],
                "description": "Currency code (BTC, ETH, or USDC)"
            },
            "kind": {
                "type": "string",
                "enum": ["future", "option", "spot", "any"],
                "default": "any",
                "description": "Instrument kind filter"
            }
        },
        "required": ["currency"]
    }
    
    currency: Optional[str] = Field(default=None, description="Currency code")
    kind: str = Field(default="any", description="Instrument kind")
    
    async def execute(self, **kwargs) -> ToolResult:
        """Execute get book summary tool"""
        try:
            currency = kwargs.get("currency", self.currency)
            kind = kwargs.get("kind", self.kind)
            
            if not currency:
                return ToolResult(error="Parameter 'currency' is required")
            
            params = {
                "currency": currency,
                "kind": kind if kind != "any" else None
            }
            
            # Remove None values
            params = {k: v for k, v in params.items() if v is not None}
            
            result = await self._call_public_method("public/get_book_summary_by_currency", params)
            
            return ToolResult(output=result)
            
        except Exception as e:
            logger.error(f"Error in GetBookSummaryTool: {e}")
            return ToolResult(error=f"Failed to get book summary: {str(e)}")

