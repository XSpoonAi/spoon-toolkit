"""Transaction-related tools for Neo N3 blockchain

These tools use only methods that are officially available in Neo N3 RPC API.
Reference: https://developers.neo.org/docs/n3/reference/rpc/api
"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider


class GetRawTransactionTool(BaseTool):
    name: str = "get_raw_transaction"
    description: str = "Get detailed transaction information by transaction hash on Neo N3 blockchain. Useful when you need to analyze transaction details, verify transaction data, or check transaction status. Returns transaction information including inputs, outputs, and other details."
    parameters: dict = {
        "type": "object",
        "properties": {
            "txid": {
                "type": "string",
                "description": "Transaction hash, must be a valid hexadecimal format"
            },
            "verbose": {
                "type": "integer",
                "description": "Verbose level (0 or 1), default is 0. Use 1 for more detailed information.",
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
        "required": ["txid"]
    }

    async def execute(self, txid: str, verbose: int = 0, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_raw_transaction(txid, verbose)
            return ToolResult(output=f"Transaction info: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetRawMempoolTool(BaseTool):
    name: str = "get_raw_mempool"
    description: str = "Get list of transactions currently in the memory pool on Neo N3 blockchain. Useful when you need to check pending transactions, monitor network activity, or see unconfirmed transactions. Returns a list of transaction hashes."
    parameters: dict = {
        "type": "object",
        "properties": {
            "should_get_unverified": {
                "type": "integer",
                "description": "If 1, get all transactions including unverified. If 0, get only verified transactions.",
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
        "required": []
    }

    async def execute(self, should_get_unverified: int = 0, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_raw_mempool(should_get_unverified)
            return ToolResult(output=f"Mempool transactions: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetTransactionHeightTool(BaseTool):
    name: str = "get_transaction_height"
    description: str = "Get the block height where a transaction was included on Neo N3 blockchain. Useful when you need to find when a transaction was confirmed or locate a transaction in the blockchain. Returns the block height as an integer."
    parameters: dict = {
        "type": "object",
        "properties": {
            "txid": {
                "type": "string",
                "description": "Transaction hash, must be a valid hexadecimal format"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["txid"]
    }

    async def execute(self, txid: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_transaction_height(txid)
            return ToolResult(output=f"Transaction height: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetApplicationLogTool(BaseTool):
    name: str = "get_application_log"
    description: str = "Get application log for a transaction on Neo N3 blockchain. Useful when you need to see smart contract execution logs, debug contract interactions, or analyze transaction execution details. Returns application log with execution details."
    parameters: dict = {
        "type": "object",
        "properties": {
            "txid": {
                "type": "string",
                "description": "Transaction hash, must be a valid hexadecimal format"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["txid"]
    }

    async def execute(self, txid: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_application_log(txid)
            return ToolResult(output=f"Application log: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

