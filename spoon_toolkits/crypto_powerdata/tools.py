"""Crypto PowerData toolkit tools for SpoonAI"""

import asyncio
import json
import logging
from typing import Dict, Any, Optional, Union
from pydantic import Field

from spoon_ai.tools.base import BaseTool, ToolResult

try:
    from .main import (
        get_cex_data_with_indicators,
        get_dex_data_with_indicators,
        get_available_indicators,
        get_cex_price,
        get_dex_token_price,
        get_global_settings,
        set_global_settings
    )
except ImportError:
    from main import (
        get_cex_data_with_indicators,
        get_dex_data_with_indicators,
        get_available_indicators,
        get_cex_price,
        get_dex_token_price,
        get_global_settings,
        set_global_settings
    )

logger = logging.getLogger(__name__)


class CryptoPowerDataBaseTool(BaseTool):
    """Base class for Crypto PowerData tools"""

    def __init__(self, **kwargs):
        # Don't override class-level parameters - let each tool class define its own
        super().__init__(**kwargs)
        # Initialize global settings if not already done
        try:
            get_global_settings()
        except Exception:
            set_global_settings()


class CryptoPowerDataCEXTool(CryptoPowerDataBaseTool):
    """Tool for fetching CEX (Centralized Exchange) data with technical indicators"""

    name: str = "crypto_powerdata_cex"
    description: str = "Fetch cryptocurrency data from centralized exchanges (100+ exchanges via CCXT) with comprehensive technical indicators"

    parameters: dict = {
        "type": "object",
        "properties": {
            "exchange": {
                "type": "string",
                "description": "Exchange identifier (e.g., 'binance', 'coinbase', 'kraken')"
            },
            "symbol": {
                "type": "string",
                "description": "Trading pair symbol (e.g., 'BTC/USDT', 'ETH/USD')"
            },
            "timeframe": {
                "type": "string",
                "default": "1h",
                "description": "Timeframe (e.g., '1m', '5m', '1h', '4h', '1d')"
            },
            "limit": {
                "type": "integer",
                "default": 100,
                "description": "Number of candles to fetch (1-500)"
            },
            "indicators_config": {
                "type": "string",
                "default": '{"ema": [{"timeperiod": 12}, {"timeperiod": 26}], "rsi": [{"timeperiod": 14}]}',
                "description": "JSON string with indicator configuration"
            },
            "use_enhanced": {
                "type": "boolean",
                "default": True,
                "description": "Use enhanced indicator system"
            }
        },
        "required": ["exchange", "symbol"]
    }

    exchange: Optional[str] = Field(default=None, description="Exchange identifier (e.g., 'binance', 'coinbase', 'kraken')")
    symbol: Optional[str] = Field(default=None, description="Trading pair symbol (e.g., 'BTC/USDT', 'ETH/USD')")
    timeframe: str = Field(default="1h", description="Timeframe (e.g., '1m', '5m', '1h', '4h', '1d')")
    limit: int = Field(default=100, description="Number of candles to fetch (1-500)")
    indicators_config: str = Field(
        default='{"ema": [{"timeperiod": 12}, {"timeperiod": 26}], "rsi": [{"timeperiod": 14}]}',
        description="JSON string with indicator configuration"
    )
    use_enhanced: bool = Field(default=True, description="Use enhanced indicator system")

    async def execute(self, **kwargs) -> ToolResult:
        """Execute CEX data fetching with indicators"""
        try:
            # Override parameters with kwargs if provided
            exchange = kwargs.get('exchange', self.exchange)
            symbol = kwargs.get('symbol', self.symbol)
            timeframe = kwargs.get('timeframe', self.timeframe)
            limit = kwargs.get('limit', self.limit)
            indicators_config = kwargs.get('indicators_config', self.indicators_config)
            use_enhanced = kwargs.get('use_enhanced', self.use_enhanced)

            # Validate required parameters
            if not exchange:
                return ToolResult(error="Parameter 'exchange' is required")
            if not symbol:
                return ToolResult(error="Parameter 'symbol' is required")

            # Call the async function
            result = await get_cex_data_with_indicators(
                exchange=exchange,
                symbol=symbol,
                timeframe=timeframe,
                limit=limit,
                indicators_config=indicators_config,
                use_enhanced=use_enhanced
            )

            if result.get('success', False):
                return ToolResult(
                    output=result['data']
                )
            else:
                return ToolResult(
                    error=result.get('error', 'Unknown error occurred')
                )

        except Exception as e:
            logger.error(f"Error in CryptoPowerDataCEXTool: {e}")
            return ToolResult(
                error=f"Tool execution failed: {str(e)}"
            )


class CryptoPowerDataDEXTool(CryptoPowerDataBaseTool):
    """Tool for fetching DEX (Decentralized Exchange) data with technical indicators"""

    name: str = "crypto_powerdata_dex"
    description: str = "Fetch cryptocurrency data from decentralized exchanges via OKX DEX API with technical indicators"

    parameters: dict = {
        "type": "object",
        "properties": {
            "chain_index": {
                "type": "string",
                "description": "Blockchain chain index (e.g., '1' for Ethereum, '56' for BSC)"
            },
            "token_address": {
                "type": "string",
                "description": "Token contract address"
            },
            "timeframe": {
                "type": "string",
                "default": "1h",
                "description": "Timeframe (e.g., '1m', '1h', '4h', '1d')"
            },
            "limit": {
                "type": "integer",
                "default": 100,
                "description": "Number of candles to fetch (1-300)"
            },
            "indicators_config": {
                "type": "string",
                "default": '{"ema": [{"timeperiod": 12}, {"timeperiod": 26}], "rsi": [{"timeperiod": 14}]}',
                "description": "JSON string with indicator configuration"
            },
            "use_enhanced": {
                "type": "boolean",
                "default": True,
                "description": "Use enhanced indicator system"
            }
        },
        "required": ["chain_index", "token_address"]
    }

    chain_index: Optional[str] = Field(default=None, description="Blockchain chain index (e.g., '1' for Ethereum, '56' for BSC)")
    token_address: Optional[str] = Field(default=None, description="Token contract address")
    timeframe: str = Field(default="1h", description="Timeframe (e.g., '1m', '1h', '4h', '1d')")
    limit: int = Field(default=100, description="Number of candles to fetch (1-300)")
    indicators_config: str = Field(
        default='{"ema": [{"timeperiod": 12}, {"timeperiod": 26}], "rsi": [{"timeperiod": 14}]}',
        description="JSON string with indicator configuration"
    )
    use_enhanced: bool = Field(default=True, description="Use enhanced indicator system")

    async def execute(self, **kwargs) -> ToolResult:
        """Execute DEX data fetching with indicators"""
        try:
            # Override parameters with kwargs if provided
            chain_index = kwargs.get('chain_index', self.chain_index)
            token_address = kwargs.get('token_address', self.token_address)
            timeframe = kwargs.get('timeframe', self.timeframe)
            limit = kwargs.get('limit', self.limit)
            indicators_config = kwargs.get('indicators_config', self.indicators_config)
            use_enhanced = kwargs.get('use_enhanced', self.use_enhanced)

            # Validate required parameters
            if not chain_index:
                return ToolResult(error="Parameter 'chain_index' is required")
            if not token_address:
                return ToolResult(error="Parameter 'token_address' is required")

            # Call the async function
            result = await get_dex_data_with_indicators(
                chain_index=chain_index,
                token_address=token_address,
                timeframe=timeframe,
                limit=limit,
                indicators_config=indicators_config,
                use_enhanced=use_enhanced
            )

            if result.get('success', False):
                return ToolResult(
                    output=result['data']
                )
            else:
                return ToolResult(
                    error=result.get('error', 'Unknown error occurred')
                )

        except Exception as e:
            logger.error(f"Error in CryptoPowerDataDEXTool: {e}")
            return ToolResult(
                error=f"Tool execution failed: {str(e)}"
            )


class CryptoPowerDataIndicatorsTool(CryptoPowerDataBaseTool):
    """Tool for getting information about available technical indicators"""

    name: str = "crypto_powerdata_indicators"
    description: str = "Get information about all available technical indicators and their parameters"

    parameters: dict = {
        "type": "object",
        "properties": {},
        "required": []
    }

    async def execute(self, **kwargs) -> ToolResult:
        """Execute indicators information retrieval"""
        try:
            # Call the async function
            result = await get_available_indicators()

            if result.get('success', False):
                return ToolResult(
                    output=result['data']
                )
            else:
                return ToolResult(
                    error=result.get('error', 'Unknown error occurred')
                )

        except Exception as e:
            logger.error(f"Error in CryptoPowerDataIndicatorsTool: {e}")
            return ToolResult(
                error=f"Tool execution failed: {str(e)}"
            )


class CryptoPowerDataPriceTool(CryptoPowerDataBaseTool):
    """Tool for getting real-time cryptocurrency prices"""

    name: str = "crypto_powerdata_price"
    description: str = "Get real-time cryptocurrency prices from CEX or DEX"

    parameters: dict = {
        "type": "object",
        "properties": {
            "source": {
                "type": "string",
                "description": "Data source: 'cex' or 'dex'"
            },
            "exchange": {
                "type": "string",
                "description": "Exchange identifier (for CEX, e.g., 'binance', 'coinbase')"
            },
            "symbol": {
                "type": "string",
                "description": "Trading symbol (for CEX, e.g., 'BTC/USDT', 'ETH/USD')"
            },
            "market_type": {
                "type": "string",
                "default": "spot",
                "description": "Market type for CEX: 'spot', 'future', 'option', 'swap'"
            },
            "chain_index": {
                "type": "string",
                "description": "Blockchain chain index (for DEX, e.g., '1' for Ethereum)"
            },
            "token_address": {
                "type": "string",
                "description": "Token contract address (for DEX)"
            }
        },
        "required": ["source"]
    }

    source: Optional[str] = Field(default=None, description="Data source: 'cex' or 'dex'")
    # CEX parameters
    exchange: Optional[str] = Field(default=None, description="Exchange identifier (for CEX)")
    symbol: Optional[str] = Field(default=None, description="Trading symbol (for CEX)")
    market_type: str = Field(default="spot", description="Market type for CEX: 'spot', 'future', 'option', 'swap'")
    # DEX parameters
    chain_index: Optional[str] = Field(default=None, description="Blockchain chain index (for DEX)")
    token_address: Optional[str] = Field(default=None, description="Token contract address (for DEX)")

    async def execute(self, **kwargs) -> ToolResult:
        """Execute price fetching"""
        try:
            # Override parameters with kwargs if provided
            source = kwargs.get('source', self.source)

            # Validate required parameters
            if not source:
                return ToolResult(error="Parameter 'source' is required")

            source = source.lower()

            if source == 'cex':
                exchange = kwargs.get('exchange', self.exchange)
                symbol = kwargs.get('symbol', self.symbol)
                market_type = kwargs.get('market_type', self.market_type)

                if not exchange or not symbol:
                    return ToolResult(
                        error="For CEX source, both 'exchange' and 'symbol' parameters are required"
                    )

                result = await get_cex_price(
                    exchange=exchange,
                    symbol=symbol,
                    market_type=market_type
                )

            elif source == 'dex':
                chain_index = kwargs.get('chain_index', self.chain_index)
                token_address = kwargs.get('token_address', self.token_address)

                if not chain_index or not token_address:
                    return ToolResult(
                        error="For DEX source, both 'chain_index' and 'token_address' parameters are required"
                    )

                result = await get_dex_token_price(
                    chain_index=chain_index,
                    token_address=token_address
                )

            else:
                return ToolResult(
                    error="Invalid source. Must be 'cex' or 'dex'"
                )

            if result.get('success', False):
                return ToolResult(
                    output=result['data']
                )
            else:
                return ToolResult(
                    error=result.get('error', 'Unknown error occurred')
                )

        except Exception as e:
            logger.error(f"Error in CryptoPowerDataPriceTool: {e}")
            return ToolResult(
                error=f"Tool execution failed: {str(e)}"
            )
