"""Account management tools for Deribit API (Private methods)"""

import logging
from typing import Any, Dict, Optional
from pydantic import Field

from .base import DeribitBaseTool, ToolResult

logger = logging.getLogger(__name__)


class GetAccountSummaryTool(DeribitBaseTool):
    """Get account summary including balance, equity, and margin information"""
    
    name: str = "deribit_get_account_summary"
    description: str = (
        "Get account summary for a specific currency. "
        "Returns balance, equity, available funds, margin, positions value, etc."
    )
    
    parameters: dict = {
        "type": "object",
        "properties": {
            "currency": {
                "type": "string",
                "enum": ["BTC", "ETH", "USDC"],
                "description": "Currency code (BTC, ETH, or USDC)"
            },
            "extended": {
                "type": "boolean",
                "default": False,
                "description": "Include extended account information"
            }
        },
        "required": ["currency"]
    }
    
    currency: Optional[str] = Field(default=None, description="Currency code")
    extended: bool = Field(default=False, description="Extended information")
    
    async def execute(self, **kwargs) -> ToolResult:
        """Execute get account summary tool"""
        try:
            currency = kwargs.get("currency", self.currency)
            extended = kwargs.get("extended", self.extended)
            
            if not currency:
                return ToolResult(error="Parameter 'currency' is required")
            
            params = {
                "currency": currency,
                "extended": extended
            }
            
            result = await self._call_private_method("private/get_account_summary", params)
            
            return ToolResult(output=result)
            
        except Exception as e:
            logger.error(f"Error in GetAccountSummaryTool: {e}")
            return ToolResult(error=f"Failed to get account summary: {str(e)}")


class GetPositionsTool(DeribitBaseTool):
    """Get current positions"""
    
    name: str = "deribit_get_positions"
    description: str = (
        "Get current positions for a specific currency and kind. "
        "Returns position details including size, entry price, mark price, PnL, etc."
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
                "enum": ["future", "option", "any"],
                "default": "any",
                "description": "Position kind filter"
            }
        },
        "required": ["currency"]
    }
    
    currency: Optional[str] = Field(default=None, description="Currency code")
    kind: str = Field(default="any", description="Position kind")
    
    async def execute(self, **kwargs) -> ToolResult:
        """Execute get positions tool"""
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
            
            result = await self._call_private_method("private/get_positions", params)
            
            return ToolResult(output=result)
            
        except Exception as e:
            logger.error(f"Error in GetPositionsTool: {e}")
            return ToolResult(error=f"Failed to get positions: {str(e)}")


class GetOrderHistoryTool(DeribitBaseTool):
    """Get order history for an instrument"""
    
    name: str = "deribit_get_order_history"
    description: str = (
        "Get order history for a specific instrument. "
        "Returns historical orders including filled, cancelled, and rejected orders."
    )
    
    parameters: dict = {
        "type": "object",
        "properties": {
            "instrument_name": {
                "type": "string",
                "description": "Instrument name (e.g., 'BTC-PERPETUAL')"
            },
            "count": {
                "type": "integer",
                "default": 20,
                "description": "Number of orders to return (1-1000)"
            },
            "offset": {
                "type": "integer",
                "default": 0,
                "description": "Offset for pagination"
            }
        },
        "required": ["instrument_name"]
    }
    
    instrument_name: Optional[str] = Field(default=None, description="Instrument name")
    count: int = Field(default=20, description="Number of orders")
    offset: int = Field(default=0, description="Offset")
    
    async def execute(self, **kwargs) -> ToolResult:
        """Execute get order history tool"""
        try:
            instrument_name = kwargs.get("instrument_name", self.instrument_name)
            count = kwargs.get("count", self.count)
            offset = kwargs.get("offset", self.offset)
            
            if not instrument_name:
                return ToolResult(error="Parameter 'instrument_name' is required")
            
            # Validate count
            if count < 1 or count > 1000:
                return ToolResult(error="Parameter 'count' must be between 1 and 1000")
            
            params = {
                "instrument_name": instrument_name,
                "count": count,
                "offset": offset
            }
            
            result = await self._call_private_method("private/get_order_history_by_instrument", params)
            
            return ToolResult(output=result)
            
        except Exception as e:
            logger.error(f"Error in GetOrderHistoryTool: {e}")
            return ToolResult(error=f"Failed to get order history: {str(e)}")


class GetTradeHistoryTool(DeribitBaseTool):
    """Get trade history for an instrument"""
    
    name: str = "deribit_get_trade_history"
    description: str = (
        "Get trade history (executed trades) for a specific instrument. "
        "Returns executed trades with price, amount, direction, timestamp, etc."
    )
    
    parameters: dict = {
        "type": "object",
        "properties": {
            "instrument_name": {
                "type": "string",
                "description": "Instrument name (e.g., 'BTC-PERPETUAL')"
            },
            "count": {
                "type": "integer",
                "default": 20,
                "description": "Number of trades to return (1-1000)"
            },
            "offset": {
                "type": "integer",
                "default": 0,
                "description": "Offset for pagination"
            }
        },
        "required": ["instrument_name"]
    }
    
    instrument_name: Optional[str] = Field(default=None, description="Instrument name")
    count: int = Field(default=20, description="Number of trades")
    offset: int = Field(default=0, description="Offset")
    
    async def execute(self, **kwargs) -> ToolResult:
        """Execute get trade history tool"""
        try:
            instrument_name = kwargs.get("instrument_name", self.instrument_name)
            count = kwargs.get("count", self.count)
            offset = kwargs.get("offset", self.offset)
            
            if not instrument_name:
                return ToolResult(error="Parameter 'instrument_name' is required")
            
            # Validate count
            if count < 1 or count > 1000:
                return ToolResult(error="Parameter 'count' must be between 1 and 1000")
            
            params = {
                "instrument_name": instrument_name,
                "count": count,
                "offset": offset
            }
            
            result = await self._call_private_method("private/get_user_trades_by_instrument", params)
            
            return ToolResult(output=result)
            
        except Exception as e:
            logger.error(f"Error in GetTradeHistoryTool: {e}")
            return ToolResult(error=f"Failed to get trade history: {str(e)}")

