"""Utility Tools for Neo N3 Blockchain

These tools use only methods that are officially available in Neo N3 RPC API.
Reference: https://developers.neo.org/docs/n3/reference/rpc/api
"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider


class ValidateAddressTool(BaseTool):
    name: str = "validate_address"
    description: str = "Validate Neo N3 address format validity using local validation. Useful when you need to verify address format before using it in other operations or validate user input. Returns True if address is valid."
    parameters: dict = {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Address string to validate"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["address"]
    }

    async def execute(self, address: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            is_valid = provider.validate_address(address)
            return ToolResult(output=f"Address validation result: {is_valid}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetUnclaimedGasTool(BaseTool):
    name: str = "get_unclaimed_gas"
    description: str = "Get unclaimed gas for a Neo N3 address. Useful when you need to check available unclaimed gas that can be claimed by the address, calculate claimable rewards, or monitor gas accumulation. Returns the unclaimed gas amount as a string."
    parameters: dict = {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Neo N3 address to get unclaimed gas for"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["address"]
    }

    async def execute(self, address: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_unclaimed_gas(address)
            return ToolResult(output=f"Unclaimed gas: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

