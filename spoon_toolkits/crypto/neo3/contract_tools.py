"""Contract-related tools for Neo N3 blockchain

These tools use only methods that are officially available in Neo N3 RPC API.
Reference: https://developers.neo.org/docs/n3/reference/rpc/api
"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider


class GetContractStateTool(BaseTool):
    name: str = "get_contract_state"
    description: str = "Get contract state information by contract script hash on Neo N3 blockchain. Useful when you need to verify contract details, analyze contract properties, or check contract deployment information. Returns contract state information including name, hash, and other details."
    parameters: dict = {
        "type": "object",
        "properties": {
            "script_hash": {
                "type": "string",
                "description": "Contract script hash, must be valid hexadecimal format (e.g., 0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5)"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["script_hash"]
    }

    async def execute(self, script_hash: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_contract_state(script_hash)
            # Convert result to string if it's an object
            if hasattr(result, '__dict__'):
                import json
                result_str = json.dumps(result.__dict__, indent=2, default=str)
            else:
                result_str = str(result)
            return ToolResult(output=f"Contract state: {result_str}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetStorageTool(BaseTool):
    name: str = "get_storage"
    description: str = "Get storage value by contract script hash and key on Neo N3 blockchain. Useful when you need to read contract storage data, verify stored values, or analyze contract state. Returns the storage value as a string."
    parameters: dict = {
        "type": "object",
        "properties": {
            "script_hash": {
                "type": "string",
                "description": "Contract script hash, must be valid hexadecimal format (e.g., 0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5)"
            },
            "key": {
                "type": "string",
                "description": "Storage key to retrieve"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["script_hash", "key"]
    }

    async def execute(self, script_hash: str, key: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_storage(script_hash, key)
            return ToolResult(output=f"Storage value: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class InvokeFunctionTool(BaseTool):
    name: str = "invoke_function"
    description: str = "Invoke a smart contract function on Neo N3 blockchain. Useful when you need to call contract methods, test contract functions, or simulate contract execution. Returns the invocation result with execution details."
    parameters: dict = {
        "type": "object",
        "properties": {
            "script_hash": {
                "type": "string",
                "description": "Contract script hash, must be valid hexadecimal format (e.g., 0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5)"
            },
            "operation": {
                "type": "string",
                "description": "Function name to invoke"
            },
            "params": {
                "type": "array",
                "description": "Function parameters (optional)",
                "items": {
                    "type": "string"
                }
            },
            "sender": {
                "type": "string",
                "description": "Sender address (optional)"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["script_hash", "operation"]
    }

    async def execute(self, script_hash: str, operation: str, params: list = None, sender: str = None, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.invoke_function(script_hash, operation, params, sender)
            return ToolResult(output=f"Invocation result: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetNativeContractsTool(BaseTool):
    name: str = "get_native_contracts"
    description: str = "Get the list of native contracts on Neo N3 blockchain. Useful when you need to understand system contracts, analyze native contract details, or verify contract information. Returns a list of native contracts with their details."
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
            result = await provider.get_native_contracts()
            return ToolResult(output=f"Native contracts: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

