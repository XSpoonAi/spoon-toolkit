"""NEP standard tools for Neo blockchain"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider

class GetNep11BalanceTool(BaseTool):
    name: str = "get_nep11_balance"
    description: str = "Get NEP-11 token (NFT) balance for a specific address and asset on Neo blockchain. Useful when you need to check NFT holdings or verify NFT balance for a specific address and asset. Returns a list of token IDs owned by the address."
    parameters: dict = {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Neo address, supports standard format and script hash format (e.g., NiEtVMWVYgpXrWkRTMwRaMJtJ41gD3912N, 0xaad8073e6df9caaf6abc0749250eb0b800c0e6f4)"
            },
            "asset_hash": {
                "type": "string",
                "description": "Asset hash, must be valid hexadecimal format (e.g., 0x1234567890abcdef)"
            },
            "token_id": {
                "type": "string",
                "description": "NFT token ID, base64 format (e.g., QmxpbmQgQm94IDIxNQ==)"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["address", "asset_hash", "token_id"]
    }

    async def execute(self, address: str, asset_hash: str, token_id: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            validated_address = await provider._validate_address(address)
            response = await provider._make_request("GetNep11Balance", {
                "ContractHash": asset_hash,
                "Address": validated_address,
                "TokenId": token_id
            })
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-11 balance: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetNep11OwnedByAddressTool(BaseTool):
    name: str = "get_nep11_owned_by_address"
    description: str = "Get all NEP-11 tokens (NFTs) owned by a specific address on Neo blockchain. Useful when you need to check NFT holdings or analyze NFT ownership for a specific address. Returns a JSON object with NFT token details."
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
            response = await provider._make_request("GetNep11OwnedByAddress", {"Address": validated_address})
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-11 tokens: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetNep11ByAddressAndHashTool(BaseTool):
    name: str = "get_nep11_by_address_and_hash"
    description: str = "Get detailed NEP-11 token information by address and asset hash on Neo blockchain. Useful when you need to get detailed NFT information for a specific address and asset combination. Returns NEP-11 token details."
    parameters: dict = {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Neo address, supports standard format and script hash format (e.g., NiEtVMWVYgpXrWkRTMwRaMJtJ41gD3912N, 0xaad8073e6df9caaf6abc0749250eb0b800c0e6f4)"
            },
            "asset_hash": {
                "type": "string",
                "description": "Asset hash, must be valid hexadecimal format (e.g., 0x1234567890abcdef)"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["address", "asset_hash"]
    }

    async def execute(self, address: str, asset_hash: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            validated_address = await provider._validate_address(address)
            response = await provider._make_request("GetNep11ByAddressAndHash", {
                "Address": validated_address,
                "ContractHash": asset_hash
            })
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-11 tokens: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetNep11TransferByAddressTool(BaseTool):
    name: str = "get_nep11_transfer_by_address"
    description: str = "Get NEP-11 token transfer records by address on Neo blockchain. Useful when you need to track NFT transfer history or analyze NFT transaction patterns for a specific address. Returns NEP-11 transfer data."
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
            response = await provider._make_request("GetNep11TransferByAddress", {"Address": validated_address})
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-11 transfers: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetNep11TransferByBlockHeightTool(BaseTool):
    name: str = "get_nep11_transfer_by_block_height"
    description: str = "Get NEP-11 token transfer records in a block by block height on Neo blockchain. Useful when you need to analyze NFT transfers in a specific block or track NFT activity by block position. Returns NEP-11 transfer data."
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
            response = await provider._make_request("GetNep11TransferByBlockHeight", {"BlockHeight": block_height})
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-11 transfers: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetNep11TransferByTransactionHashTool(BaseTool):
    name: str = "get_nep11_transfer_by_transaction_hash"
    description: str = "Get NEP-11 token transfer details by transaction hash on Neo blockchain. Useful when you need to analyze specific NFT transfer transactions or verify NFT transfer details. Returns NEP-11 transfer details."
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
            response = await provider._make_request("GetNep11TransferByTransactionHash", {"TransactionHash": transaction_hash})
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-11 transfers: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetNep11TransferCountByAddressTool(BaseTool):
    name: str = "get_nep11_transfer_count_by_address"
    description: str = "Get NEP-11 token transfer count statistics by address on Neo blockchain. Useful when you need to analyze NFT activity level or track NFT transfer frequency for a specific address. Returns an integer representing the transfer count."
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
            response = await provider._make_request("GetNep11TransferCountByAddress", {"Address": validated_address})
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-11 transfer count: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetNep17TransferByAddressTool(BaseTool):
    name: str = "get_nep17_transfer_by_address"
    description: str = "Get NEP-17 token transfer records by address on Neo blockchain. Useful when you need to track fungible token transfer history or analyze token transaction patterns for a specific address. Returns NEP-17 transfer data."
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
            response = await provider._make_request("GetNep17TransferByAddress", {"Address": validated_address})
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-17 transfers: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetNep17TransferByBlockHeightTool(BaseTool):
    name: str = "get_nep17_transfer_by_block_height"
    description: str = "Get NEP-17 token transfer records in a block by block height on Neo blockchain. Useful when you need to analyze fungible token transfers in a specific block or track token activity by block position. Returns NEP-17 transfer data."
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
            response = await provider._make_request("GetNep17TransferByBlockHeight", {"BlockHeight": block_height})
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-17 transfers: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetNep17TransferByContractHashTool(BaseTool):
    name: str = "get_nep17_transfer_by_contract_hash"
    description: str = "Get NEP-17 token transfer records by contract hash on Neo blockchain. Useful when you need to analyze token transfers for a specific contract or track contract token activity. Returns NEP-17 transfer data."
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
            response = await provider._make_request("GetNep17TransferByContractHash", {"ContractHash": contract_hash})
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-17 transfers: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetNep17TransferByTransactionHashTool(BaseTool):
    name: str = "get_nep17_transfer_by_transaction_hash"
    description: str = "Get NEP-17 token transfer details by transaction hash on Neo blockchain. Useful when you need to analyze specific token transfer transactions or verify token transfer details. Returns NEP-17 transfer details."
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
            response = await provider._make_request("GetNep17TransferByTransactionHash", {"TransactionHash": transaction_hash})
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-17 transfers: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetNep17TransferCountByAddressTool(BaseTool):
    name: str = "get_nep17_transfer_count_by_address"
    description: str = "Get NEP-17 token transfer count statistics by address on Neo blockchain. Useful when you need to analyze token activity level or track token transfer frequency for a specific address. Returns an integer representing the transfer count."
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
            response = await provider._make_request("GetNep17TransferCountByAddress", {"Address": validated_address})
            result = provider._handle_response(response)
            return ToolResult(output=f"NEP-17 transfer count: {result}")
        except Exception as e:
            return ToolResult(error=str(e)) 