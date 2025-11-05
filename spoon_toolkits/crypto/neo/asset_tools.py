"""Asset-related tools for Neo blockchain"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider

class GetAssetCountTool(BaseTool):
    name: str = "get_asset_count"
    description: str = "Get total number of assets on Neo blockchain. Useful when you need to understand the scale of assets on the network or analyze asset distribution. Returns an integer representing the total asset count."
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
            response = await provider._make_request("GetAssetCount", {})
            result = provider._handle_response(response)
            return ToolResult(output=f"Asset count: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetAssetInfoByHashTool(BaseTool):
    name: str = "get_asset_info_by_hash"
    description: str = "Get detailed asset information by asset hash on Neo blockchain. Useful when you need to verify asset details or analyze specific asset properties. Returns asset information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "asset_hash": {
                "type": "string",
                "description": "Asset hash, must be a valid hexadecimal format (e.g., 0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5)"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["asset_hash"]
    }

    async def execute(self, asset_hash: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("GetAssetInfoByHash", {"AssetHash": asset_hash})
            result = provider._handle_response(response)
            return ToolResult(output=f"Asset info: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetAssetInfoByNameTool(BaseTool):
    name: str = "get_asset_info_by_name"
    description: str = "Search Neo blockchain assets by human-readable name with fuzzy matching support. Useful when you need to verify NEP-17 or NEP-11 asset details. Returns a JSON object with keys: type, hash, symbol, tokenname, decimals, totalsupply, holders, firsttransfertime, ispopular."
    parameters: dict = {
        "type": "object",
        "properties": {
            "asset_name": {
                "type": "string",
                "description": "Asset name on Neo blockchain, supports fuzzy matching, e.g., 'NEO', 'GAS', 'FLM'"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["asset_name"]
    }

    async def execute(self, asset_name: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("GetAssetInfoByName", {"AssetName": asset_name})
            result = provider._handle_response(response)
            return ToolResult(output=f"Asset info: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetAssetsInfoByUserAddressTool(BaseTool):
    name: str = "get_assets_info_by_user_address"
    description: str = "Get all assets owned by a specific address on Neo blockchain. Useful when you need to check all assets owned by an address or analyze portfolio composition. Returns a JSON object with asset details including balance information."
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
            validated_address = await provider._validate_address(address)
            response = await provider._make_request("GetAssetsInfoByUserAddress", {"Address": validated_address})
            result = provider._handle_response(response)
            return ToolResult(output=f"Assets info: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetAssetInfoByAssetAndAddressTool(BaseTool):
    name: str = "get_asset_info_by_asset_and_address"
    description: str = "Get specific asset balance and details for a particular address on Neo blockchain. Useful when you need to check specific asset balance or details for a particular address. Returns a JSON object with asset and balance information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "asset_hash": {
                "type": "string",
                "description": "Asset hash, must be a valid hexadecimal format"
            },
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
        "required": ["asset_hash", "address"]
    }

    async def execute(self, asset_hash: str, address: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            validated_address = await provider._validate_address(address)
            response = await provider._make_request("GetAssetInfoByAssetAndAddress", {
                "AssetHash": asset_hash,
                "Address": validated_address
            })
            result = provider._handle_response(response)
            return ToolResult(output=f"Asset info: {result}")
        except Exception as e:
            return ToolResult(error=str(e)) 