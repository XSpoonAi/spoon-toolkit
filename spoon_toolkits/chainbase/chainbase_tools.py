import os
import traceback
from typing import List, Optional, Dict, Any

from spoon_ai.tools.base import BaseTool
import requests


class GetLatestBlockNumberTool(BaseTool):
    name: str = "get_latest_block_number"
    description: str = "Get the latest block height of blockchain network"
    parameters: str = {
        "type": "object",
        "properties": {
            "chain_id": {
                "type": "integer",
                "description": "Chain network ID (e.g. 1 for Ethereum, 137 for Polygon)"
            }
        },
        "required": ["chain_id"]
    }

    async def execute(self, chain_id: int = 1) -> Dict[str, Any]:
        try:
            api_key = os.getenv("CHAINBASE_API_KEY")
            if not api_key:
                raise ValueError("Missing CHAINBASE_API_KEY in environment variables!")

            url = "https://api.chainbase.online/v1/block/number/latest"
            headers = {"x-api-key": api_key}
            querystring = {"chain_id": int(chain_id)}
            
            response = requests.request("GET", url, headers=headers, params=querystring)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}


class GetBlockByNumberTool(BaseTool):
    name: str = "get_block_by_number"
    description: str = "Get the block by number of blockchain network"
    parameters: str = {
        "type": "object",
        "properties": {
            "chain_id": {
                "type": "integer",
                "description": "Chain network ID (e.g. 1 for Ethereum, 137 for Polygon)"
            },
            "number": {
                "type": "integer",
                "description": "Block number"
            }
        },
        "required": ["chain_id", "number"]
    }

    async def execute(self, chain_id: int = 1, number: int = 1) -> Dict[str, Any]:
        try:
            api_key = os.getenv("CHAINBASE_API_KEY")
            if not api_key:
                raise ValueError("Missing CHAINBASE_API_KEY in environment variables!")

            url = "https://api.chainbase.online/v1/block/detail"
            headers = {"x-api-key": api_key}
            querystring = {"chain_id": int(chain_id), "number": int(number)}
            
            response = requests.request("GET", url, headers=headers, params=querystring)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}


class GetTransactionByHashTool(BaseTool):
    name: str = "get_transaction_by_hash"
    description: str = "Get the transaction by hash of blockchain network"
    parameters: str = {
        "type": "object",
        "properties": {
            "chain_id": {
                "type": "integer",
                "description": "Chain network ID (e.g. 1 for Ethereum, 137 for Polygon)"
            },
            "hash": {
                "type": "string",
                "description": "Transaction hash"
            },
            "block_number": {
                "type": "integer",
                "description": "Block number of the transaction (optional)"
            },
            "tx_index": {
                "type": "integer",
                "description": "Transaction index of the block (optional)"
            }
        },
        "required": ["chain_id"]
    }

    async def execute(
        self, 
        chain_id: int = 1, 
        hash: Optional[str] = None,
        block_number: Optional[int] = None,
        tx_index: Optional[int] = None
    ) -> Dict[str, Any]:
        try:
            api_key = os.getenv("CHAINBASE_API_KEY")
            if not api_key:
                raise ValueError("Missing CHAINBASE_API_KEY in environment variables!")

            url = "https://api.chainbase.online/v1/tx/detail"
            headers = {"x-api-key": api_key}
            querystring = {"chain_id": int(chain_id)}
            
            if hash:
                querystring["hash"] = hash
            if block_number:
                querystring["block_number"] = int(block_number)
            if tx_index:
                querystring["tx_index"] = int(tx_index)
                
            response = requests.request("GET", url, headers=headers, params=querystring)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}


class GetAccountTransactionsTool(BaseTool):
    name: str = "get_transactions_by_account"
    description: str = "Returns the transactions from a specific wallet address"
    parameters: str = {
        "type": "object",
        "properties": {
            "chain_id": {
                "type": "integer",
                "description": "Chain network ID (e.g. 1 for Ethereum, 137 for Polygon)"
            },
            "address": {
                "type": "string",
                "description": "A hex string referencing a wallet address"
            },
            "from_block": {
                "type": "string",
                "description": "Inclusive from block number (hex string or int)"
            },
            "to_block": {
                "type": "string",
                "description": "Inclusive to block number (hex string, int, or 'latest')"
            },
            "limit": {
                "type": "integer",
                "description": "The desired page size limit (default: 10, max: 100)"
            },
            "page": {
                "type": "integer",
                "description": "The page offset (default: 1)"
            }
        },
        "required": ["chain_id", "address"]
    }

    async def execute(
        self,
        chain_id: int = 1,
        address: str = None,
        from_block: Optional[str] = None,
        to_block: Optional[str] = None,
        from_timestamp: Optional[int] = None,
        end_timestamp: Optional[int] = None,
        page: int = 1,
        limit: int = 10
    ) -> Dict[str, Any]:
        try:
            api_key = os.getenv("CHAINBASE_API_KEY")
            if not api_key:
                raise ValueError("Missing CHAINBASE_API_KEY in environment variables!")

            url = "https://api.chainbase.online/v1/account/txs"
            headers = {"x-api-key": api_key}
            
            # Build query parameters
            querystring = {"chain_id": int(chain_id), "address": address, "page": page, "limit": limit}
            
            # Add optional parameters
            if from_block:
                querystring["from_block"] = from_block
            if to_block:
                querystring["to_block"] = to_block
            if from_timestamp:
                querystring["from_timestamp"] = from_timestamp
            if end_timestamp:
                querystring["end_timestamp"] = end_timestamp
                
            response = requests.request("GET", url, headers=headers, params=querystring)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}


class ContractCallTool(BaseTool):
    name: str = "contract_call"
    description: str = "Calls a specific function for the specified contract"
    parameters: str = {
        "type": "object",
        "properties": {
            "chain_id": {
                "type": "integer",
                "description": "Chain network ID (e.g. 1 for Ethereum, 137 for Polygon)"
            },
            "contract_address": {
                "type": "string",
                "description": "A hex string referencing a contract address"
            },
            "function_name": {
                "type": "string",
                "description": "The name of the function to call"
            },
            "abi": {
                "type": "string",
                "description": "The ABI of the contract function"
            },
            "params": {
                "type": "array",
                "description": "The parameters to pass to the function"
            },
            "to_block": {
                "type": "string",
                "description": "Block number to execute the call at (can be a number or 'latest')"
            }
        },
        "required": ["chain_id", "contract_address", "function_name", "abi"]
    }

    async def execute(
        self,
        chain_id: int = 1,
        contract_address: str = None,
        function_name: str = None,
        abi: str = None,
        params: List = None,
        to_block: str = "latest"
    ) -> Dict[str, Any]:
        try:
            api_key = os.getenv("CHAINBASE_API_KEY")
            if not api_key:
                raise ValueError("Missing CHAINBASE_API_KEY in environment variables!")

            url = "https://api.chainbase.online/v1/contract/call"
            headers = {
                "x-api-key": api_key,
                "Content-Type": "application/json"
            }
            
            # Build request payload
            payload = {
                "chain_id": int(chain_id),
                "contract_address": contract_address,
                "function_name": function_name,
                "abi": abi,
                "params": params if params else [],
                "to_block": to_block
            }
            
            response = requests.request("POST", url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}


class GetAccountTokensTool(BaseTool):
    name: str = "get_account_tokens"
    description: str = "Retrieve all token balances for all ERC20 tokens for a specified address"
    parameters: str = {
        "type": "object",
        "properties": {
            "chain_id": {
                "type": "integer",
                "description": "Chain network ID (e.g. 1 for Ethereum, 137 for Polygon)"
            },
            "address": {
                "type": "string",
                "description": "A hex string referencing a wallet address"
            },
            "contract_address": {
                "type": "string",
                "description": "The address of the token contract, or filter multiple addresses (max 100)"
            },
            "limit": {
                "type": "integer",
                "description": "The desired page size limit (default: 20, max: 100)"
            },
            "page": {
                "type": "integer",
                "description": "The page offset (default: 1)"
            }
        },
        "required": ["chain_id", "address"]
    }

    async def execute(
        self,
        chain_id: int = 1,
        address: str = None,
        contract_address: Optional[str] = None,
        limit: int = 20,
        page: int = 1
    ) -> Dict[str, Any]:
        try:
            api_key = os.getenv("CHAINBASE_API_KEY")
            if not api_key:
                raise ValueError("Missing CHAINBASE_API_KEY in environment variables!")

            url = "https://api.chainbase.online/v1/account/tokens"
            headers = {"x-api-key": api_key}
            
            querystring = {"chain_id": int(chain_id), "address": address, "page": page, "limit": limit}
            if contract_address:
                querystring["contract_address"] = contract_address
                
            response = requests.request("GET", url, headers=headers, params=querystring)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}


class GetAccountNFTsTool(BaseTool):
    name: str = "get_account_nfts"
    description: str = "Get the list of NFTs owned by an account"
    parameters: str = {
        "type": "object",
        "properties": {
            "chain_id": {
                "type": "integer",
                "description": "Chain network ID (e.g. 1 for Ethereum, 137 for Polygon)"
            },
            "address": {
                "type": "string",
                "description": "A hex string referencing a wallet address"
            },
            "contract_address": {
                "type": "string",
                "description": "The address of the NFT contract, or filter multiple addresses (max 100)"
            },
            "limit": {
                "type": "integer",
                "description": "The desired page size limit (default: 20, max: 100)"
            },
            "page": {
                "type": "integer",
                "description": "The page offset (default: 1)"
            }
        },
        "required": ["chain_id", "address"]
    }

    async def execute(
        self,
        chain_id: int = 1,
        address: str = None,
        contract_address: Optional[str] = None,
        limit: int = 20,
        page: int = 1
    ) -> Dict[str, Any]:
        try:
            api_key = os.getenv("CHAINBASE_API_KEY")
            if not api_key:
                raise ValueError("Missing CHAINBASE_API_KEY in environment variables!")

            url = "https://api.chainbase.online/v1/account/nfts"
            headers = {"x-api-key": api_key}
            
            querystring = {"chain_id": int(chain_id), "address": address, "page": page, "limit": limit}
            if contract_address:
                querystring["contract_address"] = contract_address
                
            response = requests.request("GET", url, headers=headers, params=querystring)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}


class GetAccountBalanceTool(BaseTool):
    name: str = "get_account_balance"
    description: str = "Returns the native token balance for a specified address"
    parameters: str = {
        "type": "object",
        "properties": {
            "chain_id": {
                "type": "integer",
                "description": "Chain network ID (e.g. 1 for Ethereum, 137 for Polygon)"
            },
            "address": {
                "type": "string",
                "description": "A hex string referencing a wallet address"
            },
            "to_block": {
                "type": "string",
                "description": "Block decimal number, hex number or 'latest'"
            }
        },
        "required": ["chain_id", "address"]
    }

    async def execute(
        self,
        chain_id: int = 1,
        address: str = None,
        to_block: Optional[str] = None
    ) -> Dict[str, Any]:
        try:
            api_key = os.getenv("CHAINBASE_API_KEY")
            if not api_key:
                raise ValueError("Missing CHAINBASE_API_KEY in environment variables!")

            url = "https://api.chainbase.online/v1/account/balance"
            headers = {"x-api-key": api_key}
            
            querystring = {"chain_id": int(chain_id), "address": address}
            if to_block:
                querystring["to_block"] = to_block
                
            response = requests.request("GET", url, headers=headers, params=querystring)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}


class GetTokenMetadataTool(BaseTool):
    name: str = "get_token_metadata"
    description: str = "Get the metadata of a specified token"
    parameters: str = {
        "type": "object",
        "properties": {
            "chain_id": {
                "type": "integer",
                "description": "Chain network ID (e.g. 1 for Ethereum, 137 for Polygon)"
            },
            "contract_address": {
                "type": "string",
                "description": "The address of the token contract"
            }
        },
        "required": ["chain_id", "contract_address"]
    }

    async def execute(
        self,
        chain_id: int = 1,
        contract_address: str = None
    ) -> Dict[str, Any]:
        try:
            api_key = os.getenv("CHAINBASE_API_KEY")
            if not api_key:
                raise ValueError("Missing CHAINBASE_API_KEY in environment variables!")

            url = "https://api.chainbase.online/v1/token/metadata"
            headers = {"x-api-key": api_key}
            
            querystring = {"chain_id": int(chain_id), "contract_address": contract_address}
                
            response = requests.request("GET", url, headers=headers, params=querystring)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}


async def test_get_latest_block_number():
    tool = GetLatestBlockNumberTool()
    result = await tool.execute(chain_id=1)
    print("🧪 Get Latest Block Number Result:\n", result)


async def test_get_account_tokens():
    tool = GetAccountTokensTool()
    result = await tool.execute(
        chain_id=1,
        address="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # vitalik.eth
    )
    print("🧪 Get Account Tokens Result:\n", result)


async def test_get_account_balance():
    tool = GetAccountBalanceTool()
    result = await tool.execute(
        chain_id=1,
        address="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # vitalik.eth
    )
    print("🧪 Get Account Balance Result:\n", result)


if __name__ == '__main__':
    import asyncio

    async def run_all_tests():
        await test_get_latest_block_number()
        await test_get_account_tokens()
        await test_get_account_balance()

    asyncio.run(run_all_tests()) 