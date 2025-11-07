"""Address-related tools for Neo blockchain"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider

class GetAddressCountTool(BaseTool):
    name: str = "get_address_count"
    description: str = "Get total number of addresses on Neo blockchain. Useful when you need to understand network scale or analyze Neo blockchain adoption. Returns an integer representing the total address count."
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
            result = await provider.get_address_count()
            return ToolResult(output=f"Address count: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetAddressInfoTool(BaseTool):
    name: str = "get_address_info"
    description: str = "Get detailed address information on Neo blockchain. Useful when you need to analyze address activity or verify address details. Returns a JSON object with keys: address, firstusetime, lastusetime, transactionssent."
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
            result = await provider.get_address_info(address)
            return ToolResult(output=f"Address info: {result}")
        except Exception as e:
            return ToolResult(error=str(e))



class GetActiveAddressesTool(BaseTool):
    name: str = "get_active_addresses"
    description: str = "Get active address counts for specified days on Neo blockchain. Useful when you need to analyze network activity patterns or understand network participation trends. Returns a list of daily active address counts."
    parameters: dict = {
        "type": "object",
        "properties": {
            "days": {
                "type": "integer",
                "description": "Number of days to query for active addresses",
                "minimum": 1,
                "maximum": 365
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["days"]
    }

    async def execute(self, days: int, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            result = await provider.get_active_addresses(days)
            if not result:
                return ToolResult(output="Active addresses data not available with current neo-mamba implementation")
            return ToolResult(output=f"Active addresses: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetTagByAddressesTool(BaseTool):
    name: str = "get_tag_by_addresses"
    description: str = "Get detailed tag information for multiple addresses on Neo blockchain. Useful when you need to analyze address holdings or categorize addresses by their token balances. Returns a JSON object with address tag information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "addresses": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "List of Neo addresses, supports standard format and script hash format"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["addresses"]
    }

    async def execute(self, addresses: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            # Convert string to list if needed
            if isinstance(addresses, str):
                addresses = [addr.strip() for addr in addresses.split(",")]

            # Note: neo-mamba doesn't have a direct GetTagByAddresses method
            # For now, we'll get basic balance information for each address
            results = {}
            for addr in addresses:
                try:
                    addr_info = await provider.get_address_info(addr)
                    results[addr] = addr_info
                except Exception as e:
                    results[addr] = {"error": str(e)}

            return ToolResult(output=f"Address information: {results}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetTotalSentAndReceivedTool(BaseTool):
    name: str = "get_total_sent_and_received"
    description: str = "Get total sent and received amounts for a specific token contract and address on Neo blockchain. Useful when you need to analyze token transaction patterns or calculate total volume for a specific token. Returns a JSON object with keys: Address, ContractHash, received, sent."
    parameters: dict = {
        "type": "object",
        "properties": {
            "contract_hash": {
                "type": "string",
                "description": "Contract hash, must be a valid Neo contract hash format"
            },
            "address": {
                "type": "string",
                "description": "Neo address, must be a valid Neo address format"
            },
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": ["contract_hash", "address"]
    }

    async def execute(self, contract_hash: str, address: str, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            validated_address = await provider._validate_address(address)

            # Note: neo-mamba doesn't have GetTotalSentAndReceived method
            # We'll use get_nep17_transfers to get transfer history
            transfers = await provider.rpc_client.get_nep17_transfers(validated_address)

            # Calculate totals from transfer history
            sent_total = 0
            received_total = 0

            if transfers and 'sent' in transfers:
                for transfer in transfers['sent']:
                    if transfer.get('contract') == contract_hash:
                        sent_total += int(transfer.get('amount', 0))

            if transfers and 'received' in transfers:
                for transfer in transfers['received']:
                    if transfer.get('contract') == contract_hash:
                        received_total += int(transfer.get('amount', 0))

            result = {
                "address": address,
                "contract_hash": contract_hash,
                "sent": sent_total,
                "received": received_total
            }

            return ToolResult(output=f"Total sent and received: {result}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetRawTransactionByAddressTool(BaseTool):
    name: str = "get_raw_transaction_by_address"
    description: str = "Get raw transaction data by address on Neo blockchain. Useful when you need to analyze transaction details or verify transaction history for a specific address. Returns raw transaction data."
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
            # Note: neo-mamba doesn't have GetRawTransactionByAddress method
            # We'll use get_nep17_transfers as an alternative
            transfers = await provider.rpc_client.get_nep17_transfers(validated_address)
            return ToolResult(output=f"Transfer data: {transfers}")
        except Exception as e:
            return ToolResult(error=str(e))

class GetTransferByAddressTool(BaseTool):
    name: str = "get_transfer_by_address"
    description: str = "Get transfer records by address on Neo blockchain. Useful when you need to track asset transfers or analyze transfer patterns for a specific address. Returns transfer data."
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
            # Use neo-mamba's get_nep17_transfers method
            transfers = await provider.rpc_client.get_nep17_transfers(validated_address)
            return ToolResult(output=f"Transfer data: {transfers}")
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
            # Note: neo-mamba doesn't have a direct NEP-11 method
            # NEP-11 tokens would need to be queried through contract interactions
            return ToolResult(output="NEP-11 token ownership query not available with current neo-mamba implementation")
        except Exception as e:
            return ToolResult(error=str(e))