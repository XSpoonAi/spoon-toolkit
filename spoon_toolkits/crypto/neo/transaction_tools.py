"""Transaction-related tools for Neo blockchain"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider

class GetTransactionCountTool(BaseTool):
    name: str = "get_transaction_count"
    description: str = "Get total number of transactions on Neo blockchain. Useful when you need to understand network activity or analyze transaction volume trends. Returns an integer representing the total transaction count."
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
            response = await provider._make_request("GetTransactionCount", {})
            result = provider._handle_response(response)
            return ToolResult(output=f"Transaction count: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetRawTransactionByHashTool(BaseTool):
    name: str = "get_raw_transaction_by_hash"
    description: str = "Get raw transaction data by transaction hash on Neo blockchain. Useful when you need to analyze transaction details or verify transaction information. Returns raw transaction data."
    parameters: dict = {
        "type": "object",
        "properties": {
            "transaction_hash": {
                "type": "string",
                "description": "Transaction hash, must be valid hexadecimal format (e.g., 0x1234567890abcdef)"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["transaction_hash"]
    }

    async def execute(self, transaction_hash: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("GetRawTransactionByHash", {"TransactionHash": transaction_hash})
            result = provider._handle_response(response)
            return ToolResult(output=f"Raw transaction: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetRawTransactionByBlockHashTool(BaseTool):
    name: str = "get_raw_transaction_by_block_hash"
    description: str = "Get all raw transactions in a block by block hash on Neo blockchain. Useful when you need to analyze all transactions in a specific block or verify block contents. Returns raw transaction data."
    parameters: dict = {
        "type": "object",
        "properties": {
            "block_hash": {
                "type": "string",
                "description": "Block hash, must be valid hexadecimal format (e.g., 0x1234567890abcdef)"
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
            response = await provider._make_request("GetRawTransactionByBlockHash", {"BlockHash": block_hash})
            result = provider._handle_response(response)
            return ToolResult(output=f"Raw transactions: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetRawTransactionByBlockHeightTool(BaseTool):
    name: str = "get_raw_transaction_by_block_height"
    description: str = "Get all raw transactions in a block by block height on Neo blockchain. Useful when you need to analyze transactions in a specific block by its position in the blockchain. Returns raw transaction data."
    parameters: dict = {
        "type": "object",
        "properties": {
            "block_height": {
                "type": "integer",
                "description": "Block height, must be greater than or equal to 0"
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
            response = await provider._make_request("GetRawTransactionByBlockHeight", {"BlockHeight": block_height})
            result = provider._handle_response(response)
            return ToolResult(output=f"Raw transactions: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetRawTransactionByTransactionHashTool(BaseTool):
    name: str = "get_raw_transaction_by_transaction_hash"
    description: str = "Get raw transaction data by transaction hash on Neo blockchain (same functionality as GetRawTransactionByHashTool). Useful when you need to retrieve raw transaction data for analysis or verification. Returns raw transaction data."
    parameters: dict = {
        "type": "object",
        "properties": {
            "transaction_hash": {
                "type": "string",
                "description": "Transaction hash, must be valid hexadecimal format (e.g., 0x1234567890abcdef)"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["transaction_hash"]
    }

    async def execute(self, transaction_hash: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("GetRawTransactionByTransactionHash", {"TransactionHash": transaction_hash})
            result = provider._handle_response(response)
            return ToolResult(output=f"Raw transaction: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetTransferByBlockHashTool(BaseTool):
    name: str = "get_transfer_by_block_hash"
    description: str = "Get all transfer records in a block by block hash on Neo blockchain. Useful when you need to analyze asset transfers in a specific block or track transfer patterns. Returns transfer data."
    parameters: dict = {
        "type": "object",
        "properties": {
            "block_hash": {
                "type": "string",
                "description": "Block hash, must be valid hexadecimal format (e.g., 0x1234567890abcdef)"
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
            response = await provider._make_request("GetTransferByBlockHash", {"BlockHash": block_hash})
            result = provider._handle_response(response)
            return ToolResult(output=f"Transfers: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetTransferByBlockHeightTool(BaseTool):
    name: str = "get_transfer_by_block_height"
    description: str = "Get all transfer records in a block by block height on Neo blockchain. Useful when you need to analyze asset transfers in a specific block by its position in the blockchain. Returns transfer data."
    parameters: dict = {
        "type": "object",
        "properties": {
            "block_height": {
                "type": "integer",
                "description": "Block height, must be greater than or equal to 0"
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
            response = await provider._make_request("GetTransferByBlockHeight", {"BlockHeight": block_height})
            result = provider._handle_response(response)
            return ToolResult(output=f"Transfers: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetTransferEventByTransactionHashTool(BaseTool):
    name: str = "get_transfer_event_by_transaction_hash"
    description: str = "Get transfer event details by transaction hash on Neo blockchain. Useful when you need to analyze specific transfer events or verify transfer details in a transaction. Returns transfer event details."
    parameters: dict = {
        "type": "object",
        "properties": {
            "transaction_hash": {
                "type": "string",
                "description": "Transaction hash, must be valid hexadecimal format (e.g., 0x1234567890abcdef)"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["transaction_hash"]
    }

    async def execute(self, transaction_hash: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("GetTransferEventByTransactionHash", {"TransactionHash": transaction_hash})
            result = provider._handle_response(response)
            return ToolResult(output=f"Transfer events: {result}")
        except Exception as e:
            return ToolResult(error=str(e)) 