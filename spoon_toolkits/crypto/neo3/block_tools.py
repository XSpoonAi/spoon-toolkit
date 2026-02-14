"""Block-related tools for Neo N3 blockchain

These tools use only methods that are officially available in Neo N3 RPC API.
Reference: https://developers.neo.org/docs/n3/reference/rpc/api
"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider


class GetBlockCountTool(BaseTool):
    name: str = "get_block_count"
    description: str = "Get total number of blocks on Neo N3 blockchain. Useful when you need to understand blockchain growth or verify current block height. Returns an integer representing the total block count."
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


class GetBestBlockHashTool(BaseTool):
    name: str = "get_best_block_hash"
    description: str = "Get the hash of the latest block in the Neo N3 blockchain. Useful when you need to get the most recent block hash or verify blockchain state. Returns the best block hash."
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
            result = await provider.get_best_block_hash()
            return ToolResult(output=f"Best block hash: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetBlockByHashTool(BaseTool):
    name: str = "get_block_by_hash"
    description: str = "Get detailed block information by block hash on Neo N3 blockchain. Useful when you need to analyze specific block details or verify block data. Returns block information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "block_hash": {
                "type": "string",
                "description": "Block hash, must be a valid hexadecimal format"
            },
            "verbose": {
                "type": "integer",
                "description": "Verbose level (0 or 1), default is 0",
                "enum": [0, 1],
                "default": 0
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

    async def execute(self, block_hash: str, verbose: int = 0, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_block(block_hash, verbose)
            return ToolResult(output=f"Block info: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetBlockByHeightTool(BaseTool):
    name: str = "get_block_by_height"
    description: str = "Get block information by block height on Neo N3 blockchain. Useful when you need to retrieve block data by position or analyze historical blocks. Returns block information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "block_height": {
                "type": "integer",
                "description": "Block height, must be a non-negative integer",
                "minimum": 0
            },
            "verbose": {
                "type": "integer",
                "description": "Verbose level (0 or 1), default is 0",
                "enum": [0, 1],
                "default": 0
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

    async def execute(self, block_height: int, verbose: int = 0, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_block(str(block_height), verbose)
            return ToolResult(output=f"Block info: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetBlockHashTool(BaseTool):
    name: str = "get_block_hash"
    description: str = "Get block hash by block index on Neo N3 blockchain. Useful when you need to get block hash from block height. Returns block hash."
    parameters: dict = {
        "type": "object",
        "properties": {
            "index": {
                "type": "integer",
                "description": "Block index/height, must be a non-negative integer",
                "minimum": 0
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["index"]
    }

    async def execute(self, index: int, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_block_hash(index)
            return ToolResult(output=f"Block hash: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetBlockHeaderTool(BaseTool):
    name: str = "get_block_header"
    description: str = "Get block header information by block hash or height on Neo N3 blockchain. Useful when you need block header data without full block details, verify block headers, or analyze block metadata. Returns block header information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "hash_or_index": {
                "type": "string",
                "description": "Block hash (hexadecimal) or block index/height (as string)"
            },
            "verbose": {
                "type": "integer",
                "description": "Verbose level (0 or 1), default is 0",
                "enum": [0, 1],
                "default": 0
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["hash_or_index"]
    }

    async def execute(self, hash_or_index: str, verbose: int = 0, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_block_header(hash_or_index, verbose)
            return ToolResult(output=f"Block header: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

