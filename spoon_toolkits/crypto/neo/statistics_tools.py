"""Statistics and Monitoring Tools for Neo Blockchain"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider


class GetNetworkStatisticsTool(BaseTool):
    name: str = "get_network_statistics"
    description: str = "Get comprehensive network statistics for Neo blockchain. Useful when you need to understand network performance, analyze network metrics, or monitor network health. Returns network statistics information."
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
            response = await provider._make_request("GetNetworkStatistics", {})
            result = provider._handle_response(response)
            return ToolResult(output=f"Network statistics: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetTransactionStatisticsTool(BaseTool):
    name: str = "get_transaction_statistics"
    description: str = "Get transaction statistics for a time range on Neo blockchain. Useful when you need to analyze transaction trends over time or monitor transaction volume patterns. Returns transaction statistics information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "start_time": {
                "type": "string",
                "description": "Start time, ISO 8601 format (e.g., 2023-01-01T00:00:00Z)"
            },
            "end_time": {
                "type": "string",
                "description": "End time, ISO 8601 format (e.g., 2023-12-31T23:59:59Z)"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": []
    }

    async def execute(self, start_time: str = None, end_time: str = None, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            params = {}
            if start_time:
                params["start_time"] = start_time
            if end_time:
                params["end_time"] = end_time
            
            response = await provider._make_request("GetTransactionStatistics", params)
            result = provider._handle_response(response)
            return ToolResult(output=f"Transaction statistics: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetAddressStatisticsTool(BaseTool):
    name: str = "get_address_statistics"
    description: str = "Get statistics for a specific address on Neo blockchain. Useful when you need to analyze address activity patterns or track address performance metrics. Returns address statistics information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Neo address, supports standard format and script hash format (e.g., NiEtVMWVYgpXrWkRTMwRaMJtJ41gD3912N, 0xaad8073e6df9caaf6abc0749250eb0b800c0e6f4)"
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
            response = await provider._make_request("GetAddressStatistics", {
                "address": address
            })
            result = provider._handle_response(response)
            return ToolResult(output=f"Address statistics: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetContractStatisticsTool(BaseTool):
    name: str = "get_contract_statistics"
    description: str = "Get statistics for a specific contract on Neo blockchain. Useful when you need to analyze contract usage patterns or track contract performance metrics. Returns contract statistics information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "contract_hash": {
                "type": "string",
                "description": "Contract hash, must be valid hexadecimal format (e.g., 0x1234567890abcdef)"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["contract_hash"]
    }

    async def execute(self, contract_hash: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("GetContractStatistics", {
                "contract_hash": contract_hash
            })
            result = provider._handle_response(response)
            return ToolResult(output=f"Contract statistics: {result}")
        except Exception as e:
            return ToolResult(error=str(e)) 