"""Smart Contract Call Tools for Neo Blockchain"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider


class InvokeContractTool(BaseTool):
    name: str = "invoke_contract"
    description: str = "Execute smart contract methods on Neo blockchain. Useful when you need to execute smart contract functions or interact with deployed contracts on the Neo blockchain. Returns the execution result from the contract."
    parameters: dict = {
        "type": "object",
        "properties": {
            "contract_hash": {
                "type": "string",
                "description": "Contract hash, must be valid hexadecimal format (e.g., 0x1234567890abcdef)"
            },
            "method": {
                "type": "string", 
                "description": "Method name to invoke"
            },
            "params": {
                "type": "array",
                "description": "Method parameters list, provide according to contract method requirements",
                "items": {
                    "type": "string"
                }
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["contract_hash", "method"]
    }

    async def execute(self, contract_hash: str, method: str, params: list = None, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("InvokeContract", {
                "contract_hash": contract_hash,
                "method": method,
                "params": params or []
            })
            result = provider._handle_response(response)
            return ToolResult(output=f"Contract invocation result: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class TestInvokeContractTool(BaseTool):
    name: str = "test_invoke_contract"
    description: str = "Simulate smart contract method calls on Neo blockchain without executing transactions. Useful when you need to simulate contract calls or verify contract function behavior without executing transactions. Returns the simulated execution result."
    parameters: dict = {
        "type": "object",
        "properties": {
            "contract_hash": {
                "type": "string",
                "description": "Contract hash, must be valid hexadecimal format (e.g., 0x1234567890abcdef)"
            },
            "method": {
                "type": "string",
                "description": "Method name to test"
            },
            "params": {
                "type": "array",
                "description": "Test parameters list, provide according to contract method requirements",
                "items": {
                    "type": "string"
                }
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["contract_hash", "method"]
    }

    async def execute(self, contract_hash: str, method: str, params: list = None, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("TestInvokeContract", {
                "contract_hash": contract_hash,
                "method": method,
                "params": params or []
            })
            result = provider._handle_response(response)
            return ToolResult(output=f"Test invocation result: {result}")
        except Exception as e:
            return ToolResult(error=str(e))


class GetContractStateTool(BaseTool):
    name: str = "get_contract_state"
    description: str = "Get current state of Neo smart contracts. Useful when you need to check contract deployment status or verify contract state information. Returns contract state information."
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
            response = await provider._make_request("GetContractState", {
                "contract_hash": contract_hash
            })
            result = provider._handle_response(response)
            return ToolResult(output=f"Contract state: {result}")
        except Exception as e:
            return ToolResult(error=str(e)) 