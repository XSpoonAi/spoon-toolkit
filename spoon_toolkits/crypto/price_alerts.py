import json
import logging
import asyncio
import time
from typing import Dict, Any, List, Optional, Union, Tuple
from decimal import Decimal

import requests
from web3 import Web3, HTTPProvider
from web3.middleware import ExtraDataToPOAMiddleware
from pydantic import Field, validator

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import DexBaseTool
from .price_data import (
    PriceDataProvider,
    UniswapPriceProvider,
    TOKEN_ADDRESSES,
    UNISWAP_POOL_ABI
)

logger = logging.getLogger(__name__)

# Uniswap V3 Position Manager ABI (only includes required functions)
UNISWAP_POSITION_ABI = json.loads('''
[
  {
    "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
    "name": "positions",
    "outputs": [
      {"internalType": "uint96", "name": "nonce", "type": "uint96"},
      {"internalType": "address", "name": "operator", "type": "address"},
      {"internalType": "address", "name": "token0", "type": "address"},
      {"internalType": "address", "name": "token1", "type": "address"},
      {"internalType": "uint24", "name": "fee", "type": "uint24"},
      {"internalType": "int24", "name": "tickLower", "type": "int24"},
      {"internalType": "int24", "name": "tickUpper", "type": "int24"},
      {"internalType": "uint128", "name": "liquidity", "type": "uint128"},
      {"internalType": "uint256", "name": "feeGrowthInside0LastX128", "type": "uint256"},
      {"internalType": "uint256", "name": "feeGrowthInside1LastX128", "type": "uint256"},
      {"internalType": "uint128", "name": "tokensOwed0", "type": "uint128"},
      {"internalType": "uint128", "name": "tokensOwed1", "type": "uint128"}
    ],
    "stateMutability": "view",
    "type": "function"
  }
]
''')

# Uniswap V3 Position Manager address
UNISWAP_POSITION_MANAGER = "0xC36442b4a4522E871399CD717aBDD847Ab11FE88"

# CoinGecko API base URL
COINGECKO_API_URL = "https://api.coingecko.com/api/v3"

# Bitquery API endpoint
BITQUERY_API_URL = "https://graphql.bitquery.io"
BITQUERY_API_KEY = "" # Should be loaded from environment variables in production

class PriceAlertProvider:
    """Base class for price alert data providers"""

    async def check_price_threshold(self, symbol: str, threshold_percent: float) -> Dict[str, Any]:
        """Check if price exceeds the threshold percentage"""
        raise NotImplementedError("Subclasses must implement this method")

    async def check_lp_range(self, position_id: int, buffer_ticks: int = 100) -> Dict[str, Any]:
        """Check if LP position is within the specified range"""
        raise NotImplementedError("Subclasses must implement this method")

    async def monitor_sudden_price_increase(
        self,
        min_market_cap: float = 500000000,
        min_volume: float = 100000000,
        price_increase_percent: float = 100
    ) -> List[Dict[str, Any]]:
        """Monitor tokens with sudden price increases meeting specified criteria"""
        raise NotImplementedError("Subclasses must implement this method")

class UniswapAlertProvider(PriceAlertProvider):
    """Uniswap price alert provider"""

    def __init__(self, rpc_url: Optional[str] = None):
        self.rpc_url = rpc_url or "https://eth-mainnet.g.alchemy.com/v2/demo"
        self.w3 = Web3(HTTPProvider(self.rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        self.price_provider = UniswapPriceProvider(rpc_url=self.rpc_url)
        self.position_manager = self.w3.eth.contract(
            address=self.w3.to_checksum_address(UNISWAP_POSITION_MANAGER),
            abi=UNISWAP_POSITION_ABI
        )

    async def check_price_threshold(self, symbol: str, threshold_percent: float) -> Dict[str, Any]:
        """Check if price exceeds the threshold percentage

        Args:
            symbol: Trading pair symbol (e.g., "ETH-USDC")
            threshold_percent: Price change threshold percentage, positive for increase, negative for decrease

        Returns:
            Alert result dictionary containing threshold exceeded status, current price, 24h price, change percentage, etc.
        """
        try:
            # Get 24-hour price change data
            price_data = await self.price_provider.get_ticker_24h(symbol)

            if "error" in price_data:
                return {
                    "success": False,
                    "message": f"Failed to get price data: {price_data['error']}",
                    "symbol": symbol,
                    "exceeded": False
                }

            # Calculate price change percentage
            price_change_percent = float(price_data.get("priceChangePercent", "0"))

            # Determine if threshold is exceeded
            exceeded = False
            if threshold_percent > 0 and price_change_percent >= threshold_percent:
                # Increase exceeds threshold
                exceeded = True
                message = f"Price increased by {price_change_percent}%, exceeding threshold of {threshold_percent}%"
            elif threshold_percent < 0 and price_change_percent <= threshold_percent:
                # Decrease exceeds threshold
                exceeded = True
                message = f"Price decreased by {price_change_percent}%, exceeding threshold of {threshold_percent}%"
            else:
                message = f"Price change ({price_change_percent}%) is within threshold ({threshold_percent}%)"

            return {
                "success": True,
                "message": message,
                "symbol": symbol,
                "current_price": price_data.get("price", "0"),
                "price_change_percent": price_change_percent,
                "exceeded": exceeded,
                "threshold": threshold_percent,
                "timestamp": int(time.time())
            }
        except Exception as e:
            logger.error(f"Failed to check price threshold: {e}")
            return {
                "success": False,
                "message": f"Failed to check price threshold: {str(e)}",
                "symbol": symbol,
                "exceeded": False
            }

    async def check_lp_range(self, position_id: int, buffer_ticks: int = 100) -> Dict[str, Any]:
        """Check if LP position is within the specified range

        Args:
            position_id: Uniswap V3 position ID
            buffer_ticks: Safety buffer zone near range boundaries (in ticks)

        Returns:
            Alert result dictionary containing range status, current tick, tick range, etc.
        """
        try:
            # Get position information
            position = self.position_manager.functions.positions(position_id).call()

            # Parse position information
            token0 = position[2]
            token1 = position[3]
            fee = position[4]
            tick_lower = position[5]
            tick_upper = position[6]

            # Get pool address and current price information
            pool_address = self.price_provider._get_pool_address(token0, token1, fee)
            pool_contract = self.w3.eth.contract(address=pool_address, abi=UNISWAP_POOL_ABI)

            # Get current tick
            slot0 = pool_contract.functions.slot0().call()
            current_tick = slot0[1]

            # Determine if current price is in range and if it's near boundaries
            in_range = tick_lower <= current_tick <= tick_upper

            # Calculate distance to boundaries in ticks
            distance_to_lower = current_tick - tick_lower
            distance_to_upper = tick_upper - current_tick

            # Determine if near boundaries
            near_lower = in_range and distance_to_lower <= buffer_ticks
            near_upper = in_range and distance_to_upper <= buffer_ticks

            # Get token symbols
            try:
                token0_contract = self.w3.eth.contract(address=token0, abi=[{
                    "constant": True,
                    "inputs": [],
                    "name": "symbol",
                    "outputs": [{"name": "", "type": "string"}],
                    "payable": False,
                    "stateMutability": "view",
                    "type": "function"
                }])
                token1_contract = self.w3.eth.contract(address=token1, abi=[{
                    "constant": True,
                    "inputs": [],
                    "name": "symbol",
                    "outputs": [{"name": "", "type": "string"}],
                    "payable": False,
                    "stateMutability": "view",
                    "type": "function"
                }])

                token0_symbol = token0_contract.functions.symbol().call()
                token1_symbol = token1_contract.functions.symbol().call()
                pair = f"{token0_symbol}-{token1_symbol}"
            except Exception as e:
                logger.warning(f"Failed to get token symbols: {e}")
                pair = f"{token0}-{token1}"

            # Generate alert message
            if not in_range:
                status = "OUT_OF_RANGE"
                message = f"LP position is OUT OF RANGE! Current tick: {current_tick}, Range: [{tick_lower}, {tick_upper}]"
            elif near_lower:
                status = "NEAR_LOWER_BOUND"
                message = f"LP position is near lower bound! Distance: {distance_to_lower} ticks"
            elif near_upper:
                status = "NEAR_UPPER_BOUND"
                message = f"LP position is near upper bound! Distance: {distance_to_upper} ticks"
            else:
                status = "IN_RANGE"
                message = f"LP position is safely in range. Current tick: {current_tick}, Range: [{tick_lower}, {tick_upper}]"

            return {
                "success": True,
                "message": message,
                "position_id": position_id,
                "pair": pair,
                "current_tick": current_tick,
                "tick_lower": tick_lower,
                "tick_upper": tick_upper,
                "in_range": in_range,
                "status": status,
                "distance_to_lower": distance_to_lower if in_range else None,
                "distance_to_upper": distance_to_upper if in_range else None,
                "timestamp": int(time.time())
            }
        except Exception as e:
            logger.error(f"Failed to check LP range: {e}")
            return {
                "success": False,
                "message": f"Failed to check LP range: {str(e)}",
                "position_id": position_id
            }

    async def _get_coingecko_market_data(self, vs_currency: str = "usd", min_market_cap: float = 0, min_volume: float = 0) -> List[Dict]:
        """Get coin market data from CoinGecko that meets market cap and volume criteria"""
        try:
            # Build API URL
            url = f"{COINGECKO_API_URL}/coins/markets"
            params = {
                "vs_currency": vs_currency,
                "order": "market_cap_desc",  # Sort by market cap in descending order
                "per_page": 250,  # Maximum items per page
                "page": 1,
                "sparkline": "false",
                "price_change_percentage": "24h"
            }

            # Send request
            response = requests.get(url, params=params)
            response.raise_for_status()
            coins = response.json()

            # Filter coins meeting market cap and volume criteria
            filtered_coins = [
                coin for coin in coins
                if coin.get("market_cap", 0) >= min_market_cap
                and coin.get("total_volume", 0) >= min_volume
            ]

            return filtered_coins
        except Exception as e:
            logger.error(f"Failed to get CoinGecko market data: {e}")
            return []

    async def _get_bitquery_price_data(self, token_addresses: List[str]) -> Dict[str, Dict]:
        """Get token price data from Bitquery"""
        if not BITQUERY_API_KEY:
            raise ValueError(
                "Bitquery API key is not configured. Please set the BITQUERY_API_KEY environment variable.\n\n"
                "To obtain a Bitquery API key:\n"
                "1. Visit https://bitquery.io/\n"
                "2. Sign up for an account or log in\n"
                "3. Go to your dashboard and create an API key\n"
                "4. Copy the API key\n"
                "5. Add it to your .env file:\n"
                "   BITQUERY_API_KEY=your_api_key_here\n\n"
                "Note: This is different from BITQUERY_CLIENT_ID and BITQUERY_CLIENT_SECRET used for OAuth.\n"
                "Manage your credentials at: https://bitquery.io/dashboard"
            )

        # Build GraphQL query
        query = """
        query ($network: EthereumNetwork!, $token: String!) {
          ethereum(network: $network) {
            dexTrades(
              options: {desc: ["block.height", "transaction.index"], limit: 1}
              exchangeName: {in: ["Uniswap", "Uniswap v3"]}
              baseCurrency: {is: $token}
              quoteCurrency: {is: "0xdAC17F958D2ee523a2206206994597C13D831ec7"} # USDT
            ) {
              block {
                height
                timestamp {
                  time(format: "%Y-%m-%d %H:%M:%S")
                }
              }
              transaction {
                index
              }
              baseCurrency {
                symbol
                address
              }
              quoteCurrency {
                symbol
                address
              }
              quotePrice
              trades: count
              volume: baseAmount
              amount: quoteAmount
              maximum_price: quotePrice(calculate: maximum)
              minimum_price: quotePrice(calculate: minimum)
              open_price: minimum(of: block.height, get: quote_price)
              close_price: maximum(of: block.height, get: quote_price)
            }
          }
        }
        """

        results = {}

        # Send query for each token address
        for token in token_addresses:
            try:
                variables = {
                    "network": "ethereum",
                    "token": token
                }

                headers = {
                    "X-API-KEY": BITQUERY_API_KEY,
                    "Content-Type": "application/json"
                }

                response = requests.post(
                    BITQUERY_API_URL,
                    json={"query": query, "variables": variables},
                    headers=headers
                )
                response.raise_for_status()
                data = response.json()

                # Check if there is trade data
                dex_trades = data.get("data", {}).get("ethereum", {}).get("dexTrades", [])
                if dex_trades:
                    results[token] = dex_trades[0]

                # Respect API rate limits
                await asyncio.sleep(0.5)

            except Exception as e:
                logger.error(f"Failed to get Bitquery price data for token {token}: {e}")
                continue

        return results

    async def monitor_sudden_price_increase(
        self,
        min_market_cap: float = 500000000,
        min_volume: float = 100000000,
        price_increase_percent: float = 100
    ) -> List[Dict[str, Any]]:
        """Monitor tokens with sudden significant price increases that meet specified criteria

        Args:
            min_market_cap: Minimum market cap in USD
            min_volume: Minimum 24-hour trading volume in USD
            price_increase_percent: Price increase threshold percentage

        Returns:
            List of tokens meeting criteria, each containing token information and price change
        """
        try:
            # Get coins meeting market cap and volume criteria from CoinGecko
            coins = await self._get_coingecko_market_data(
                min_market_cap=min_market_cap,
                min_volume=min_volume
            )

            if not coins:
                return []

            # Find coins with price increase exceeding threshold
            sudden_increase_coins = []

            for coin in coins:
                price_change_24h = coin.get("price_change_percentage_24h", 0)

                # If 24h price increase exceeds threshold
                if price_change_24h >= price_increase_percent:
                    sudden_increase_coins.append({
                        "id": coin.get("id"),
                        "symbol": coin.get("symbol", "").upper(),
                        "name": coin.get("name"),
                        "current_price": coin.get("current_price"),
                        "market_cap": coin.get("market_cap"),
                        "volume_24h": coin.get("total_volume"),
                        "price_change_24h_percent": price_change_24h,
                        "threshold": price_increase_percent,
                        "market_cap_rank": coin.get("market_cap_rank"),
                        "timestamp": int(time.time())
                    })

            # Sort results by price increase in descending order
            return sorted(sudden_increase_coins, key=lambda x: x.get("price_change_24h_percent", 0), reverse=True)

        except Exception as e:
            logger.error(f"Failed to monitor sudden price increase: {e}")
            return []

class PriceThresholdAlertTool(DexBaseTool):
    """Price threshold alert tool"""
    name: str = "price_threshold_alert"
    description: str = "Monitor if a token pair's price change exceeds the specified threshold percentage"
    parameters: dict = {
        "type": "object",
        "properties": {
            "symbol": {
                "type": "string",
                "description": "Trading pair symbol (e.g., 'ETH-USDC')"
            },
            "threshold_percent": {
                "type": "number",
                "description": "Price change threshold percentage (positive for increase, negative for decrease)"
            },
            "exchange": {
                "type": "string",
                "description": "Exchange name (e.g., 'uniswap', default is 'uniswap')",
                "enum": ["uniswap"]
            }
        },
        "required": ["symbol", "threshold_percent"]
    }

    # Provider instance cache
    _providers: Dict[str, PriceAlertProvider] = {}

    def _get_provider(self, exchange: str) -> PriceAlertProvider:
        """Get or create price alert provider for specified exchange"""
        exchange = exchange.lower()
        if exchange not in self._providers:
            if exchange == "uniswap":
                self._providers[exchange] = UniswapAlertProvider()
            else:
                raise ValueError(f"Unsupported exchange: {exchange}")
        return self._providers[exchange]

    async def execute(self, symbol: str, threshold_percent: float, exchange: str = "uniswap") -> ToolResult:
        """Execute the tool"""
        try:
            provider = self._get_provider(exchange)
            result = await provider.check_price_threshold(symbol, threshold_percent)
            return ToolResult(output=result)
        except Exception as e:
            logger.error(f"Failed to execute price threshold alert: {e}")
            return ToolResult(error=f"Failed to execute price threshold alert: {str(e)}")

class LpRangeCheckTool(DexBaseTool):
    """LP range check tool"""
    name: str = "lp_range_check"
    description: str = "Check if a Uniswap V3 LP position is within the specified range or near boundaries"
    parameters: dict = {
        "type": "object",
        "properties": {
            "position_id": {
                "type": "integer",
                "description": "Uniswap V3 position NFT token ID"
            },
            "buffer_ticks": {
                "type": "integer",
                "description": "Buffer zone in ticks to consider as 'near boundary' (default: 100)",
                "default": 100
            },
            "exchange": {
                "type": "string",
                "description": "Exchange name (currently only supports 'uniswap')",
                "enum": ["uniswap"]
            }
        },
        "required": ["position_id"]
    }

    # Reuse provider instances from price threshold tool
    _providers = PriceThresholdAlertTool._providers

    def _get_provider(self, exchange: str) -> PriceAlertProvider:
        """Get or create price alert provider for specified exchange"""
        exchange = exchange.lower()
        if exchange not in self._providers:
            if exchange == "uniswap":
                self._providers[exchange] = UniswapAlertProvider()
            else:
                raise ValueError(f"Unsupported exchange: {exchange}")
        return self._providers[exchange]

    async def execute(self, position_id: int, buffer_ticks: int = 100, exchange: str = "uniswap") -> ToolResult:
        """Execute the tool"""
        try:
            provider = self._get_provider(exchange)
            result = await provider.check_lp_range(position_id, buffer_ticks)
            return ToolResult(output=result)
        except Exception as e:
            logger.error(f"Failed to execute LP range check: {e}")
            return ToolResult(error=f"Failed to execute LP range check: {str(e)}")

class SuddenPriceIncreaseTool(DexBaseTool):
    """Sudden price increase monitoring tool"""
    name: str = "monitor_sudden_price_increase"
    description: str = "Monitor tokens with sudden significant price increases that meet market cap and volume criteria"
    parameters: dict = {
        "type": "object",
        "properties": {
            "min_market_cap": {
                "type": "number",
                "description": "Minimum market cap in USD (default: 500,000,000)",
                "default": 500000000
            },
            "min_volume": {
                "type": "number",
                "description": "Minimum 24h trading volume in USD (default: 100,000,000)",
                "default": 100000000
            },
            "price_increase_percent": {
                "type": "number",
                "description": "Minimum price increase percentage to trigger alert (default: 100)",
                "default": 100
            },
            "exchange": {
                "type": "string",
                "description": "Data source (currently uses CoinGecko regardless of this parameter)",
                "enum": ["uniswap"]
            }
        }
    }

    # Reuse provider instances from price threshold tool
    _providers = PriceThresholdAlertTool._providers

    def _get_provider(self, exchange: str) -> PriceAlertProvider:
        """Get or create price alert provider for specified exchange"""
        exchange = exchange.lower()
        if exchange not in self._providers:
            if exchange == "uniswap":
                self._providers[exchange] = UniswapAlertProvider()
            else:
                raise ValueError(f"Unsupported exchange: {exchange}")
        return self._providers[exchange]

    async def execute(
        self,
        min_market_cap: float = 500000000,
        min_volume: float = 100000000,
        price_increase_percent: float = 100,
        exchange: str = "uniswap"
    ) -> ToolResult:
        """Execute the tool"""
        try:
            provider = self._get_provider(exchange)
            results = await provider.monitor_sudden_price_increase(
                min_market_cap=min_market_cap,
                min_volume=min_volume,
                price_increase_percent=price_increase_percent
            )
            return ToolResult(output=results)
        except Exception as e:
            logger.error(f"Failed to monitor sudden price increase: {e}")
            return ToolResult(error=f"Failed to monitor sudden price increase: {str(e)}")