"""Block-related tools for Neo blockchain"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider

class GetBlockCountTool(BaseTool):
    name: str = "get_block_count"
    description: str = "Get total number of blocks on Neo blockchain. Useful when you need to understand blockchain growth or verify current block height. Returns an integer representing the total block count."
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
            result = await provider.get_block_count()
            return ToolResult(output=f"Block count: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetBlockByHashTool(BaseTool):
    name: str = "get_block_by_hash"
    description: str = "Get detailed block information by block hash on Neo blockchain. Useful when you need to analyze specific block details or verify block data. Returns block information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "block_hash": {
                "type": "string",
                "description": "Block hash, must be a valid hexadecimal format"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["block_hash"]
    }

    async def execute(self, block_hash: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_block_info(block_hash)
            return ToolResult(output=f"Block info: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetBlockByHeightTool(BaseTool):
    name: str = "get_block_by_height"
    description: str = "Get block information by block height on Neo blockchain. Useful when you need to retrieve block data by position or analyze historical blocks. Returns block information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "block_height": {
                "type": "integer",
                "description": "Block height, must be a non-negative integer",
                "minimum": 0
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["block_height"]
    }

    async def execute(self, block_height: int, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_block_by_height(block_height)
            return ToolResult(output=f"Block info: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetBestBlockHashTool(BaseTool):
    name: str = "get_best_block_hash"
    description: str = "Get the current best block hash on Neo blockchain. Useful when you need to identify the latest block or verify blockchain tip. Returns the best block hash."
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
            response = await provider._make_request("GetBestBlockHash", {})
            result = provider._handle_response(response)
            return ToolResult(output=f"Best block hash: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetRecentBlocksInfoTool(BaseTool):
    name: str = "get_recent_blocks_info"
    description: str = "Get recent blocks information list on Neo blockchain. Useful when you need to monitor recent blockchain activity or analyze recent blocks. Returns recent blocks information."
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
            response = await provider._make_request("GetRecentBlocksInfo", {})
            result = provider._handle_response(response)
            return ToolResult(output=f"Recent blocks info: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetBlockRewardByHashTool(BaseTool):
    name: str = "get_block_reward_by_hash"
    description: str = "Get block reward information by block hash on Neo blockchain. Useful when you need to analyze mining rewards or verify block reward distribution. Returns block reward information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "block_hash": {
                "type": "string",
                "description": "Block hash, must be a valid hexadecimal format"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["block_hash"]
    }

    async def execute(self, block_hash: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("GetBlockRewardByHash", {"BlockHash": block_hash})
            result = provider._handle_response(response)
            return ToolResult(output=f"Block reward info: {result}")
        except Exception as e:
            return ToolResult(error=str(e))