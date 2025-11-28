"""NEP standard tools for Neo N3 blockchain

These tools use only methods that are officially available in Neo N3 RPC API.
Reference: https://developers.neo.org/docs/n3/reference/rpc/api
"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider


class GetNep17BalancesTool(BaseTool):
    name: str = "get_nep17_balances"
    description: str = "Get NEP-17 token balances for a specific address on Neo N3 blockchain. Useful when you need to check fungible token holdings or verify token balance for a specific address. Returns all NEP-17 token balances."
    parameters: dict = {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Neo address in standard format (e.g., NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp)"
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
            result = await provider.get_nep17_balances(address)
            return ToolResult(output=f"NEP-17 balances: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetNep17TransfersTool(BaseTool):
    name: str = "get_nep17_transfers"
    description: str = "Get NEP-17 token transfer history for a specific address on Neo N3 blockchain. Useful when you need to track fungible token transfer history or analyze token transaction patterns. Returns all NEP-17 transfers."
    parameters: dict = {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Neo address in standard format (e.g., NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp)"
            },
            "timestamp": {
                "type": "integer",
                "description": "Optional timestamp filter (Unix timestamp in milliseconds)"
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

    async def execute(self, address: str, timestamp: int = None, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_nep17_transfers(address, timestamp)
            return ToolResult(output=f"NEP-17 transfers: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetNep11BalancesTool(BaseTool):
    name: str = "get_nep11_balances"
    description: str = "Get NEP-11 token (NFT) balances for a specific address on Neo N3 blockchain. Useful when you need to check NFT holdings or verify NFT balance for a specific address. Returns all NEP-11 token balances."
    parameters: dict = {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Neo address in standard format (e.g., NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp)"
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
            result = await provider.get_nep11_balances(address)
            return ToolResult(output=f"NEP-11 balances: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetNep11PropertiesTool(BaseTool):
    name: str = "get_nep11_properties"
    description: str = "Get customized properties of NEP-11 assets (NFTs) on Neo N3 blockchain. Useful when you need to retrieve NFT metadata or verify NFT properties. Returns NFT properties."
    parameters: dict = {
        "type": "object",
        "properties": {
            "contract_hash": {
                "type": "string",
                "description": "Contract script hash (e.g., 0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5)"
            },
            "token_id": {
                "type": "string",
                "description": "Token ID"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["contract_hash", "token_id"]
    }

    async def execute(self, contract_hash: str, token_id: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_nep11_properties(contract_hash, token_id)
            return ToolResult(output=f"NEP-11 properties: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetNep11TransfersTool(BaseTool):
    name: str = "get_nep11_transfers"
    description: str = "Get NEP-11 token (NFT) transfer history for a specific address on Neo N3 blockchain. Useful when you need to track NFT transfer history or analyze NFT transaction patterns. Returns all NEP-11 transfers."
    parameters: dict = {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Neo address in standard format (e.g., NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp)"
            },
            "timestamp": {
                "type": "integer",
                "description": "Optional timestamp filter (Unix timestamp in milliseconds)"
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

    async def execute(self, address: str, timestamp: int = None, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_nep11_transfers(address, timestamp)
            return ToolResult(output=f"NEP-11 transfers: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

