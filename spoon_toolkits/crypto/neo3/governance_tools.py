"""Governance-related tools for Neo N3 blockchain

These tools use only methods that are officially available in Neo N3 RPC API.
Reference: https://developers.neo.org/docs/n3/reference/rpc/api
"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider


class GetCommitteeTool(BaseTool):
    name: str = "get_committee"
    description: str = "Get the public key list of current Neo N3 committee members. Useful when you need to understand governance structure, analyze committee composition, or verify committee members. Returns a list of committee member public keys."
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
            result = await provider.get_committee()
            return ToolResult(output=f"Committee members: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetNextBlockValidatorsTool(BaseTool):
    name: str = "get_next_block_validators"
    description: str = "Get the validators list of the next block on Neo N3 blockchain. Useful when you need to understand consensus mechanism, analyze validator selection, or verify next block validators. Returns a list of validators for the next block."
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
            result = await provider.get_next_block_validators()
            return ToolResult(output=f"Next block validators: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

