"""Utility Tools for Neo Blockchain"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider


class ValidateAddressTool(BaseTool):
    name: str = "validate_address"
    description: str = "Validate Neo address format validity. Useful when you need to verify address format before using it in other operations or validate user input. Returns address validation result."
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
            response = await provider._make_request("ValidateAddress", {
                "address": address
            })
            result = provider._handle_response(response)
            return ToolResult(output=f"Address validation result: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class ConvertAddressTool(BaseTool):
    name: str = "convert_address"
    description: str = "Convert Neo address format between standard and script hash representations. Useful when you need to convert between different address representations or standardize address format for different use cases. Returns converted address information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Address string to convert"
            },
            "format": {
                "type": "string",
                "description": "Target format, must be 'script' or 'address'",
                "enum": ["script", "address"],
                "default": "address"
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

    async def execute(self, address: str, format: str = "address", network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("ConvertAddress", {
                "address": address,
                "format": format
            })
            result = provider._handle_response(response)
            return ToolResult(output=f"Converted address: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetNetworkInfoTool(BaseTool):
    name: str = "get_network_info"
    description: str = "Get basic network information for Neo blockchain. Useful when you need to understand network configuration or verify network connectivity and status. Returns network information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": []
    }

    async def execute(self, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("GetNetworkInfo", {})
            result = provider._handle_response(response)
            return ToolResult(output=f"Network info: {result}")
        except Exception as e:
            return ToolResult(error=str(e)) 