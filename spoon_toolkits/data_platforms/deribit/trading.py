"""Trading tools for Deribit API (Private methods)"""

import logging
from typing import Any, Dict, Optional, Tuple
from pydantic import Field
from decimal import Decimal, ROUND_DOWN, ROUND_UP

from .base import DeribitBaseTool, ToolResult
from .market_data import GetInstrumentsTool

logger = logging.getLogger(__name__)


class ValidationResult:
    """Validation result container for pre-flight checks."""
    def __init__(self, is_valid: bool, adjusted_value: Optional[float] = None,
                 original_value: Optional[float] = None,
                 contract_size: Optional[float] = None,
                 tick_size: Optional[float] = None,
                 message: str = ""):
        self.is_valid = is_valid
        self.adjusted_value = adjusted_value
        self.original_value = original_value
        self.contract_size = contract_size
        self.tick_size = tick_size
        self.message = message

    def get_error_message(self) -> str:
        """Return a human-friendly error message."""
        if self.is_valid:
            return ""

        parts = []
        if self.contract_size:
            parts.append(f"contract size: {self.contract_size}")
        if self.tick_size:
            parts.append(f"tick size: {self.tick_size}")
        if self.original_value is not None:
            parts.append(f"original value: {self.original_value}")
        if self.adjusted_value is not None:
            parts.append(f"suggested value: {self.adjusted_value}")

        if parts:
            return f"{self.message} ({', '.join(parts)})"
        return self.message


def _adjust_amount_to_contract_size(amount: float, contract_size: float) -> float:
    """
    Adjust amount to be a multiple of contract size

    Args:
        amount: Original amount
        contract_size: Contract size (e.g., 0.0001 for ETH_USDC)

    Returns:
        Adjusted amount that is a multiple of contract size
    """
    if contract_size <= 0:
        return amount

    # Calculate the closest multiple
    multiple = round(amount / contract_size)

    # Ensure at least 1 multiple
    if multiple < 1:
        multiple = 1

    # Calculate adjusted amount
    adjusted_amount = multiple * contract_size

    # Handle floating point precision
    contract_size_str = str(contract_size)
    if '.' in contract_size_str:
        decimals = len(contract_size_str.split('.')[1])
    else:
        decimals = 0

    # Round to correct precision
    adjusted_amount = round(adjusted_amount, decimals)

    return adjusted_amount


class PlaceBuyOrderTool(DeribitBaseTool):
    """Place a buy order on Deribit"""

    name: str = "deribit_place_buy_order"
    description: str = (
        "Place a buy order on Deribit. "
        "Supports market, limit, stop_market, and stop_limit order types."
    )

    parameters: dict = {
        "type": "object",
        "properties": {
            "instrument_name": {
                "type": "string",
                "description": "Instrument name (e.g., 'BTC-PERPETUAL', 'BTC-25JAN25-50000-C')"
            },
            "amount": {
                "type": "number",
                "description": "Order amount (in contracts)"
            },
            "price": {
                "type": "number",
                "description": "Order price (required for limit orders)"
            },
            "order_type": {
                "type": "string",
                "enum": ["market", "limit", "stop_market", "stop_limit"],
                "default": "limit",
                "description": "Order type"
            },
            "time_in_force": {
                "type": "string",
                "enum": ["good_til_cancelled", "fill_or_kill", "immediate_or_cancel"],
                "default": "good_til_cancelled",
                "description": "Time in force"
            },
            "reduce_only": {
                "type": "boolean",
                "default": False,
                "description": "Reduce only order (only reduce position, not increase)"
            },
            "post_only": {
                "type": "boolean",
                "default": False,
                "description": "Post only order (maker order)"
            }
        },
        "required": ["instrument_name", "amount"]
    }

    instrument_name: Optional[str] = Field(default=None, description="Instrument name")
    amount: Optional[float] = Field(default=None, description="Order amount")
    price: Optional[float] = Field(default=None, description="Order price")
    order_type: str = Field(default="limit", description="Order type")
    time_in_force: str = Field(default="good_til_cancelled", description="Time in force")
    reduce_only: bool = Field(default=False, description="Reduce only")
    post_only: bool = Field(default=False, description="Post only")

    async def execute(self, **kwargs) -> ToolResult:
        """Execute place buy order tool"""
        try:
            instrument_name = kwargs.get("instrument_name", self.instrument_name)
            amount = kwargs.get("amount", self.amount)
            price = kwargs.get("price", self.price)
            order_type = kwargs.get("order_type", self.order_type)
            time_in_force = kwargs.get("time_in_force", self.time_in_force)
            reduce_only = kwargs.get("reduce_only", self.reduce_only)
            post_only = kwargs.get("post_only", self.post_only)

            # Basic parameter validation
            if not instrument_name:
                return ToolResult(error="❌ Parameter error: 'instrument_name' is required")
            if amount is None:
                return ToolResult(error="❌ Parameter error: 'amount' is required")
            if amount <= 0:
                return ToolResult(error=f"❌ Parameter error: 'amount' must be greater than 0, got: {amount}")

            # Validate price for limit orders
            if order_type in ["limit", "stop_limit"] and price is None:
                return ToolResult(error=f"❌ Parameter error: '{order_type}' orders require a 'price' parameter")
            if price is not None and price <= 0:
                return ToolResult(error=f"❌ Parameter error: 'price' must be greater than 0, got: {price}")

            # Validate and adjust amount (contract size)
            amount_result = await self._validate_and_adjust_amount(instrument_name, amount)
            if not amount_result.is_valid:
                error_msg = f"❌ Amount validation failed: {amount_result.get_error_message()}"
                if amount_result.adjusted_value:
                    error_msg += (
                        f"\n💡 Suggestion: adjust 'amount' to {amount_result.adjusted_value} "
                        f"(a multiple of contract size)"
                    )
                return ToolResult(error=error_msg)

            # Log if amount was adjusted
            if amount_result.adjusted_value != amount_result.original_value:
                logger.info(
                    "Amount automatically adjusted: %s -> %s (contract size: %s)",
                    amount_result.original_value,
                    amount_result.adjusted_value,
                    amount_result.contract_size,
                )

            amount = amount_result.adjusted_value

            # Validate price precision (tick size) for limit orders
            if price is not None and order_type in ["limit", "stop_limit"]:
                price_result = await self._validate_price(instrument_name, price)
                if not price_result.is_valid:
                    error_msg = f"❌ Price validation failed: {price_result.get_error_message()}"
                    if price_result.adjusted_value:
                        error_msg += (
                            f"\n💡 Suggestion: adjust 'price' to {price_result.adjusted_value} "
                            f"(conforms to tick size)"
                        )
                    return ToolResult(error=error_msg)

                # If price was adjusted, log and use adjusted value
                if price_result.adjusted_value != price_result.original_value:
                    logger.info(
                        "Price automatically adjusted: %s -> %s (tick size: %s)",
                        price_result.original_value,
                        price_result.adjusted_value,
                        price_result.tick_size,
                    )
                price = price_result.adjusted_value

                # Format price with proper precision based on tick_size
                if price_result.tick_size:
                    tick_size_str = str(price_result.tick_size)
                    if '.' in tick_size_str:
                        decimals = len(tick_size_str.split('.')[1])
                    else:
                        decimals = 0
                    price = round(price, decimals)

            params = {
                "instrument_name": instrument_name,
                "amount": amount,
                "type": order_type,
                "time_in_force": time_in_force,
                "reduce_only": reduce_only,
                "post_only": post_only
            }

            if price is not None:
                params["price"] = price

            result = await self._call_private_method("private/buy", params)

            return ToolResult(output=result)

        except Exception as e:
            logger.error(f"Error in PlaceBuyOrderTool: {e}")
            return ToolResult(error=f"Failed to place buy order: {str(e)}")

    async def _validate_price(self, instrument_name: str, price: float) -> ValidationResult:
        """
        Validate and adjust price to conform to tick size

        Args:
            instrument_name: Instrument name
            price: Original price

        Returns:
            ValidationResult with validation status and adjusted price
        """
        try:
            # Query instrument to get tick_size
            instruments_tool = GetInstrumentsTool()

            # Extract currency from instrument name
            currency = None
            if "_" in instrument_name:
                currency = instrument_name.split("_")[0]
                kind = "spot"
            elif "-" in instrument_name:
                if instrument_name.endswith("-C") or instrument_name.endswith("-P"):
                    currency = instrument_name.split("-")[0]
                    kind = "option"
                elif "PERPETUAL" in instrument_name.upper():
                    currency = instrument_name.split("-")[0]
                    kind = "future"
                else:
                    currency = instrument_name.split("-")[0]
                    kind = "future"
            else:
                for curr in ["BTC", "ETH", "USDC"]:
                    if instrument_name.startswith(curr):
                        currency = curr
                        kind = "any"
                        break

            if not currency:
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=price,
                    original_value=price,
                    message="Could not determine currency; skipping price tick-size validation",
                )

            # Query instruments
            result = await instruments_tool.execute(currency=currency, kind=kind, expired=False)

            if isinstance(result, dict) and result.get("error"):
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=price,
                    original_value=price,
                    message="Failed to query instrument specs; skipping price tick-size validation",
                )

            instruments = result.get("output") if isinstance(result, dict) else result

            if not instruments:
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=price,
                    original_value=price,
                    message="No instrument specs found; skipping price tick-size validation",
                )

            # Find matching instrument
            tick_size = None
            for inst in instruments:
                if inst.get("instrument_name") == instrument_name:
                    tick_size = inst.get("tick_size")
                    break

            if tick_size and tick_size > 0:
                # Always normalize price to conform to tick_size to avoid float precision issues
                price_decimal = Decimal(str(price))
                tick_decimal = Decimal(str(tick_size))

                # Calculate the normalized price (always round down for buy orders)
                normalized_price = (price_decimal / tick_decimal).quantize(Decimal('1'), rounding=ROUND_DOWN) * tick_decimal

                # Determine precision from tick_size
                tick_size_str = str(tick_size)
                if '.' in tick_size_str:
                    decimals = len(tick_size_str.split('.')[1])
                else:
                    decimals = 0

                # Convert to float with proper precision
                normalized_price_float = float(round(normalized_price, decimals))

                # Check if original price was significantly different
                price_diff = abs(price_decimal - normalized_price)
                tolerance = tick_decimal * Decimal('0.00001')

                if price_diff > tolerance:
                    # Price was not aligned, return adjusted value
                    return ValidationResult(
                        is_valid=False,
                        adjusted_value=normalized_price_float,
                        original_value=price,
                        tick_size=tick_size,
                        message=f"Price {price} does not conform to tick size {tick_size}",
                    )
                else:
                    # Price is valid, but still return normalized value to ensure precision
                    return ValidationResult(
                        is_valid=True,
                        adjusted_value=normalized_price_float,
                        original_value=price,
                        tick_size=tick_size
                    )
            else:
                # No tick_size found, assume valid
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=price,
                    original_value=price,
                    message="No tick-size information found; skipping validation",
                )

        except Exception as e:
            logger.warning("Error validating price for %s: %s", instrument_name, e)
            return ValidationResult(
                is_valid=True,
                adjusted_value=price,
                original_value=price,
                message=f"Price validation raised an exception: {e}",
            )

    async def _validate_and_adjust_amount(self, instrument_name: str, amount: float) -> ValidationResult:
        """
        Validate and adjust amount to be a multiple of contract size

        Args:
            instrument_name: Instrument name (e.g., 'ETH_USDC', 'ETH-PERPETUAL', 'BTC-25JAN25-50000-C')
            amount: Original amount

        Returns:
            ValidationResult with validation status and adjusted amount
        """
        try:
            # Query instrument to get contract size
            instruments_tool = GetInstrumentsTool()

            # Extract currency from instrument name
            currency = None
            if "_" in instrument_name:
                # Spot trading pair (e.g., ETH_USDC)
                currency = instrument_name.split("_")[0]
                kind = "spot"
            elif "-" in instrument_name:
                # Check if it's an option (ends with -C or -P)
                if instrument_name.endswith("-C") or instrument_name.endswith("-P"):
                    # Options (e.g., BTC-25JAN25-50000-C, ETH-25JAN25-3000-P)
                    currency = instrument_name.split("-")[0]
                    kind = "option"
                elif "PERPETUAL" in instrument_name.upper():
                    # Perpetual futures (e.g., ETH-PERPETUAL)
                    currency = instrument_name.split("-")[0]
                    kind = "future"
                else:
                    # Other futures (e.g., BTC-25JAN25, ETH-25JAN25)
                    currency = instrument_name.split("-")[0]
                    kind = "future"
            else:
                # Try to determine from instrument name
                for curr in ["BTC", "ETH", "USDC"]:
                    if instrument_name.startswith(curr):
                        currency = curr
                        kind = "any"
                        break

            if not currency:
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=amount,
                    original_value=amount,
                    message="Could not determine currency; skipping contract-size validation",
                )

            # Query instruments
            result = await instruments_tool.execute(currency=currency, kind=kind, expired=False)

            if isinstance(result, dict) and result.get("error"):
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=amount,
                    original_value=amount,
                    message=f"Failed to query instrument specs: {result.get('error')}; skipping contract-size validation",
                )

            instruments = result.get("output") if isinstance(result, dict) else result

            if not instruments:
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=amount,
                    original_value=amount,
                    message=f"No instrument specs found for {currency}; skipping contract-size validation",
                )

            # Find matching instrument
            contract_size = None
            for inst in instruments:
                if inst.get("instrument_name") == instrument_name:
                    contract_size = inst.get("contract_size")
                    break

            if contract_size and contract_size > 0:
                # Check if amount is already a multiple
                amount_decimal = Decimal(str(amount))
                contract_decimal = Decimal(str(contract_size))
                remainder = amount_decimal % contract_decimal

                # Small tolerance for floating point errors
                tolerance = contract_decimal * Decimal('0.0001')

                if remainder > tolerance and (contract_decimal - remainder) > tolerance:
                    # Amount is not a multiple, adjust it
                    adjusted_amount = _adjust_amount_to_contract_size(amount, contract_size)

                    return ValidationResult(
                        is_valid=False,
                        adjusted_value=adjusted_amount,
                        original_value=amount,
                        contract_size=contract_size,
                        message=f"Amount {amount} is not a multiple of contract size {contract_size}",
                    )
                else:
                    # Amount is already a multiple (within tolerance)
                    return ValidationResult(
                        is_valid=True,
                        adjusted_value=amount,
                        original_value=amount,
                        contract_size=contract_size
                    )
            else:
                # No contract size found
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=amount,
                    original_value=amount,
                    message=f"No contract-size information for {instrument_name}; skipping validation",
                )

        except Exception as e:
            logger.warning("Error validating contract size for %s: %s", instrument_name, e)
            return ValidationResult(
                is_valid=True,
                adjusted_value=amount,
                original_value=amount,
                message=f"Contract-size validation raised an exception: {e}",
            )


class PlaceSellOrderTool(DeribitBaseTool):
    """Place a sell order on Deribit"""

    name: str = "deribit_place_sell_order"
    description: str = (
        "Place a sell order on Deribit. "
        "Supports market, limit, stop_market, and stop_limit order types."
    )

    parameters: dict = {
        "type": "object",
        "properties": {
            "instrument_name": {
                "type": "string",
                "description": "Instrument name (e.g., 'BTC-PERPETUAL', 'BTC-25JAN25-50000-C')"
            },
            "amount": {
                "type": "number",
                "description": "Order amount (in contracts)"
            },
            "price": {
                "type": "number",
                "description": "Order price (required for limit orders)"
            },
            "order_type": {
                "type": "string",
                "enum": ["market", "limit", "stop_market", "stop_limit"],
                "default": "limit",
                "description": "Order type"
            },
            "time_in_force": {
                "type": "string",
                "enum": ["good_til_cancelled", "fill_or_kill", "immediate_or_cancel"],
                "default": "good_til_cancelled",
                "description": "Time in force"
            },
            "reduce_only": {
                "type": "boolean",
                "default": False,
                "description": "Reduce only order (only reduce position, not increase)"
            },
            "post_only": {
                "type": "boolean",
                "default": False,
                "description": "Post only order (maker order)"
            }
        },
        "required": ["instrument_name", "amount"]
    }

    instrument_name: Optional[str] = Field(default=None, description="Instrument name")
    amount: Optional[float] = Field(default=None, description="Order amount")
    price: Optional[float] = Field(default=None, description="Order price")
    order_type: str = Field(default="limit", description="Order type")
    time_in_force: str = Field(default="good_til_cancelled", description="Time in force")
    reduce_only: bool = Field(default=False, description="Reduce only")
    post_only: bool = Field(default=False, description="Post only")

    async def execute(self, **kwargs) -> ToolResult:
        """Execute place sell order tool"""
        try:
            instrument_name = kwargs.get("instrument_name", self.instrument_name)
            amount = kwargs.get("amount", self.amount)
            price = kwargs.get("price", self.price)
            order_type = kwargs.get("order_type", self.order_type)
            time_in_force = kwargs.get("time_in_force", self.time_in_force)
            reduce_only = kwargs.get("reduce_only", self.reduce_only)
            post_only = kwargs.get("post_only", self.post_only)

            # Basic parameter validation
            if not instrument_name:
                return ToolResult(error="❌ Parameter error: 'instrument_name' is required")
            if amount is None:
                return ToolResult(error="❌ Parameter error: 'amount' is required")
            if amount <= 0:
                return ToolResult(error=f"❌ Parameter error: 'amount' must be greater than 0, got: {amount}")

            # Validate price for limit orders
            if order_type in ["limit", "stop_limit"] and price is None:
                return ToolResult(error=f"❌ Parameter error: '{order_type}' orders require a 'price' parameter")
            if price is not None and price <= 0:
                return ToolResult(error=f"❌ Parameter error: 'price' must be greater than 0, got: {price}")

            # Validate and adjust amount (contract size)
            amount_result = await self._validate_and_adjust_amount(instrument_name, amount)
            if not amount_result.is_valid:
                error_msg = f"❌ Amount validation failed: {amount_result.get_error_message()}"
                if amount_result.adjusted_value:
                    error_msg += (
                        f"\n💡 Suggestion: adjust 'amount' to {amount_result.adjusted_value} "
                        f"(a multiple of contract size)"
                    )
                return ToolResult(error=error_msg)

            # Log if amount was adjusted
            if amount_result.adjusted_value != amount_result.original_value:
                logger.info(
                    "Amount automatically adjusted: %s -> %s (contract size: %s)",
                    amount_result.original_value,
                    amount_result.adjusted_value,
                    amount_result.contract_size,
                )

            amount = amount_result.adjusted_value

            # Validate price precision (tick size) for limit orders
            if price is not None and order_type in ["limit", "stop_limit"]:
                price_result = await self._validate_price(instrument_name, price)
                if not price_result.is_valid:
                    error_msg = f"❌ Price validation failed: {price_result.get_error_message()}"
                    if price_result.adjusted_value:
                        error_msg += (
                            f"\n💡 Suggestion: adjust 'price' to {price_result.adjusted_value} "
                            f"(conforms to tick size)"
                        )
                    return ToolResult(error=error_msg)

                # If price was adjusted, log and use adjusted value
                if price_result.adjusted_value != price_result.original_value:
                    logger.info(
                        "Price automatically adjusted: %s -> %s (tick size: %s)",
                        price_result.original_value,
                        price_result.adjusted_value,
                        price_result.tick_size,
                    )
                price = price_result.adjusted_value

                # Format price with proper precision based on tick_size
                if price_result.tick_size:
                    tick_size_str = str(price_result.tick_size)
                    if '.' in tick_size_str:
                        decimals = len(tick_size_str.split('.')[1])
                    else:
                        decimals = 0
                    price = round(price, decimals)

            params = {
                "instrument_name": instrument_name,
                "amount": amount,
                "type": order_type,
                "time_in_force": time_in_force,
                "reduce_only": reduce_only,
                "post_only": post_only
            }

            if price is not None:
                params["price"] = price

            result = await self._call_private_method("private/sell", params)

            return ToolResult(output=result)

        except Exception as e:
            logger.error(f"Error in PlaceSellOrderTool: {e}")
            return ToolResult(error=f"Failed to place sell order: {str(e)}")

    async def _validate_price(self, instrument_name: str, price: float) -> ValidationResult:
        """
        Validate and adjust price to conform to tick size

        Args:
            instrument_name: Instrument name
            price: Original price

        Returns:
            ValidationResult with validation status and adjusted price
        """
        try:
            # Query instrument to get tick_size
            instruments_tool = GetInstrumentsTool()

            # Extract currency from instrument name
            currency = None
            if "_" in instrument_name:
                currency = instrument_name.split("_")[0]
                kind = "spot"
            elif "-" in instrument_name:
                if instrument_name.endswith("-C") or instrument_name.endswith("-P"):
                    currency = instrument_name.split("-")[0]
                    kind = "option"
                elif "PERPETUAL" in instrument_name.upper():
                    currency = instrument_name.split("-")[0]
                    kind = "future"
                else:
                    currency = instrument_name.split("-")[0]
                    kind = "future"
            else:
                for curr in ["BTC", "ETH", "USDC"]:
                    if instrument_name.startswith(curr):
                        currency = curr
                        kind = "any"
                        break

            if not currency:
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=price,
                    original_value=price,
                    message="Could not determine currency; skipping price tick-size validation",
                )

            # Query instruments
            result = await instruments_tool.execute(currency=currency, kind=kind, expired=False)

            if isinstance(result, dict) and result.get("error"):
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=price,
                    original_value=price,
                    message="Failed to query instrument specs; skipping price tick-size validation",
                )

            instruments = result.get("output") if isinstance(result, dict) else result

            if not instruments:
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=price,
                    original_value=price,
                    message="No instrument specs found; skipping price tick-size validation",
                )

            # Find matching instrument
            tick_size = None
            for inst in instruments:
                if inst.get("instrument_name") == instrument_name:
                    tick_size = inst.get("tick_size")
                    break

            if tick_size and tick_size > 0:
                # Always normalize price to conform to tick_size to avoid float precision issues
                price_decimal = Decimal(str(price))
                tick_decimal = Decimal(str(tick_size))

                # Calculate the normalized price (round UP for sell orders to preserve minimum acceptable price)
                normalized_price = (price_decimal / tick_decimal).quantize(Decimal('1'), rounding=ROUND_UP) * tick_decimal

                # Determine precision from tick_size
                tick_size_str = str(tick_size)
                if '.' in tick_size_str:
                    decimals = len(tick_size_str.split('.')[1])
                else:
                    decimals = 0

                # Convert to float with proper precision
                normalized_price_float = float(round(normalized_price, decimals))

                # Check if original price was significantly different
                price_diff = abs(price_decimal - normalized_price)
                tolerance = tick_decimal * Decimal('0.00001')

                if price_diff > tolerance:
                    # Price was not aligned, return adjusted value
                    return ValidationResult(
                        is_valid=False,
                        adjusted_value=normalized_price_float,
                        original_value=price,
                        tick_size=tick_size,
                        message=f"Price {price} does not conform to tick size {tick_size}",
                    )
                else:
                    # Price is valid, but still return normalized value to ensure precision
                    return ValidationResult(
                        is_valid=True,
                        adjusted_value=normalized_price_float,
                        original_value=price,
                        tick_size=tick_size
                    )
            else:
                # No tick_size found, assume valid
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=price,
                    original_value=price,
                    message="No tick-size information found; skipping validation",
                )

        except Exception as e:
            logger.warning("Error validating price for %s: %s", instrument_name, e)
            return ValidationResult(
                is_valid=True,
                adjusted_value=price,
                original_value=price,
                message=f"Price validation raised an exception: {e}",
            )

    async def _validate_and_adjust_amount(self, instrument_name: str, amount: float) -> ValidationResult:
        """
        Validate and adjust amount to be a multiple of contract size

        Args:
            instrument_name: Instrument name (e.g., 'ETH_USDC', 'ETH-PERPETUAL', 'BTC-25JAN25-50000-C')
            amount: Original amount

        Returns:
            ValidationResult with validation status and adjusted amount
        """
        try:
            # Query instrument to get contract size
            instruments_tool = GetInstrumentsTool()

            # Extract currency from instrument name
            currency = None
            if "_" in instrument_name:
                # Spot trading pair (e.g., ETH_USDC)
                currency = instrument_name.split("_")[0]
                kind = "spot"
            elif "-" in instrument_name:
                # Check if it's an option (ends with -C or -P)
                if instrument_name.endswith("-C") or instrument_name.endswith("-P"):
                    # Options (e.g., BTC-25JAN25-50000-C, ETH-25JAN25-3000-P)
                    currency = instrument_name.split("-")[0]
                    kind = "option"
                elif "PERPETUAL" in instrument_name.upper():
                    # Perpetual futures (e.g., ETH-PERPETUAL)
                    currency = instrument_name.split("-")[0]
                    kind = "future"
                else:
                    # Other futures (e.g., BTC-25JAN25, ETH-25JAN25)
                    currency = instrument_name.split("-")[0]
                    kind = "future"
            else:
                # Try to determine from instrument name
                for curr in ["BTC", "ETH", "USDC"]:
                    if instrument_name.startswith(curr):
                        currency = curr
                        kind = "any"
                        break

            if not currency:
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=amount,
                    original_value=amount,
                    message="Could not determine currency; skipping contract-size validation",
                )

            # Query instruments
            result = await instruments_tool.execute(currency=currency, kind=kind, expired=False)

            if isinstance(result, dict) and result.get("error"):
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=amount,
                    original_value=amount,
                    message=f"Failed to query instrument specs: {result.get('error')}; skipping contract-size validation",
                )

            instruments = result.get("output") if isinstance(result, dict) else result

            if not instruments:
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=amount,
                    original_value=amount,
                    message=f"No instrument specs found for {currency}; skipping contract-size validation",
                )

            # Find matching instrument
            contract_size = None
            for inst in instruments:
                if inst.get("instrument_name") == instrument_name:
                    contract_size = inst.get("contract_size")
                    break

            if contract_size and contract_size > 0:
                # Check if amount is already a multiple
                amount_decimal = Decimal(str(amount))
                contract_decimal = Decimal(str(contract_size))
                remainder = amount_decimal % contract_decimal

                # Small tolerance for floating point errors
                tolerance = contract_decimal * Decimal('0.0001')

                if remainder > tolerance and (contract_decimal - remainder) > tolerance:
                    # Amount is not a multiple, adjust it
                    adjusted_amount = _adjust_amount_to_contract_size(amount, contract_size)

                    return ValidationResult(
                        is_valid=False,
                        adjusted_value=adjusted_amount,
                        original_value=amount,
                        contract_size=contract_size,
                        message=f"Amount {amount} is not a multiple of contract size {contract_size}",
                    )
                else:
                    # Amount is already a multiple (within tolerance)
                    return ValidationResult(
                        is_valid=True,
                        adjusted_value=amount,
                        original_value=amount,
                        contract_size=contract_size
                    )
            else:
                # No contract size found
                return ValidationResult(
                    is_valid=True,
                    adjusted_value=amount,
                    original_value=amount,
                    message=f"No contract-size information for {instrument_name}; skipping validation",
                )

        except Exception as e:
            logger.warning("Error validating contract size for %s: %s", instrument_name, e)
            return ValidationResult(
                is_valid=True,
                adjusted_value=amount,
                original_value=amount,
                message=f"Contract-size validation raised an exception: {e}",
            )


class CancelOrderTool(DeribitBaseTool):
    """Cancel an order on Deribit"""

    name: str = "deribit_cancel_order"
    description: str = (
        "Cancel a specific order by order ID. "
        "Returns the cancelled order information."
    )

    parameters: dict = {
        "type": "object",
        "properties": {
            "order_id": {
                "type": "string",
                "description": "Order ID to cancel"
            }
        },
        "required": ["order_id"]
    }

    order_id: Optional[str] = Field(default=None, description="Order ID")

    async def execute(self, **kwargs) -> ToolResult:
        """Execute cancel order tool"""
        try:
            order_id = kwargs.get("order_id", self.order_id)

            if not order_id:
                return ToolResult(error="Parameter 'order_id' is required")

            params = {
                "order_id": order_id
            }

            result = await self._call_private_method("private/cancel", params)

            return ToolResult(output=result)

        except Exception as e:
            logger.error(f"Error in CancelOrderTool: {e}")
            return ToolResult(error=f"Failed to cancel order: {str(e)}")


class CancelAllOrdersTool(DeribitBaseTool):
    """Cancel all orders for a currency and kind"""

    name: str = "deribit_cancel_all_orders"
    description: str = (
        "Cancel all orders for a specific currency and instrument kind. "
        "Returns the number of cancelled orders."
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
            "type": {
                "type": "string",
                "enum": ["all", "limit", "stop"],
                "default": "all",
                "description": "Order type filter"
            }
        },
        "required": ["currency"]
    }

    currency: Optional[str] = Field(default=None, description="Currency code")
    kind: str = Field(default="any", description="Instrument kind")
    type: str = Field(default="all", description="Order type filter")

    async def execute(self, **kwargs) -> ToolResult:
        """Execute cancel all orders tool"""
        try:
            currency = kwargs.get("currency", self.currency)
            kind = kwargs.get("kind", self.kind)
            order_type = kwargs.get("type", self.type)

            if not currency:
                return ToolResult(error="Parameter 'currency' is required")

            params = {
                "currency": currency,
                "kind": kind if kind != "any" else None,
                "type": order_type if order_type != "all" else None
            }

            # Remove None values
            params = {k: v for k, v in params.items() if v is not None}

            result = await self._call_private_method("private/cancel_all", params)

            return ToolResult(output=result)

        except Exception as e:
            logger.error(f"Error in CancelAllOrdersTool: {e}")
            return ToolResult(error=f"Failed to cancel all orders: {str(e)}")


class GetOpenOrdersTool(DeribitBaseTool):
    """Get open orders for an instrument"""

    name: str = "deribit_get_open_orders"
    description: str = (
        "Get all open orders for a specific instrument. "
        "Returns order details including status, price, amount, etc."
    )

    parameters: dict = {
        "type": "object",
        "properties": {
            "instrument_name": {
                "type": "string",
                "description": "Instrument name (e.g., 'BTC-PERPETUAL')"
            }
        },
        "required": ["instrument_name"]
    }

    instrument_name: Optional[str] = Field(default=None, description="Instrument name")

    async def execute(self, **kwargs) -> ToolResult:
        """Execute get open orders tool"""
        try:
            instrument_name = kwargs.get("instrument_name", self.instrument_name)

            if not instrument_name:
                return ToolResult(error="Parameter 'instrument_name' is required")

            params = {
                "instrument_name": instrument_name
            }

            result = await self._call_private_method("private/get_open_orders_by_instrument", params)

            return ToolResult(output=result)

        except Exception as e:
            logger.error(f"Error in GetOpenOrdersTool: {e}")
            return ToolResult(error=f"Failed to get open orders: {str(e)}")


class EditOrderTool(DeribitBaseTool):
    """Edit an existing order"""

    name: str = "deribit_edit_order"
    description: str = (
        "Edit an existing order by order ID. "
        "Can modify amount and/or price."
    )

    parameters: dict = {
        "type": "object",
        "properties": {
            "order_id": {
                "type": "string",
                "description": "Order ID to edit"
            },
            "amount": {
                "type": "number",
                "description": "New order amount (optional)"
            },
            "price": {
                "type": "number",
                "description": "New order price (optional)"
            }
        },
        "required": ["order_id"]
    }

    order_id: Optional[str] = Field(default=None, description="Order ID")
    amount: Optional[float] = Field(default=None, description="New amount")
    price: Optional[float] = Field(default=None, description="New price")

    async def execute(self, **kwargs) -> ToolResult:
        """Execute edit order tool"""
        try:
            order_id = kwargs.get("order_id", self.order_id)
            amount = kwargs.get("amount", self.amount)
            price = kwargs.get("price", self.price)

            if not order_id:
                return ToolResult(error="Parameter 'order_id' is required")

            if amount is None and price is None:
                return ToolResult(error="At least one of 'amount' or 'price' must be provided")

            params = {
                "order_id": order_id
            }

            if amount is not None:
                params["amount"] = amount
            if price is not None:
                # Ensure price is formatted with proper precision to avoid float precision issues
                # Convert to string first, then back to float to ensure exact representation
                price_str = f"{price:.10f}".rstrip('0').rstrip('.')
                params["price"] = float(price_str)

            result = await self._call_private_method("private/edit", params)

            return ToolResult(output=result)

        except Exception as e:
            logger.error(f"Error in EditOrderTool: {e}")
            return ToolResult(error=f"Failed to edit order: {str(e)}")
