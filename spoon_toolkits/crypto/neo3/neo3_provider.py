"""Neo N3 blockchain data provider

This module provides a comprehensive interface for interacting with the Neo N3 blockchain
using neo-mamba library. It only includes methods that are officially available in the
Neo N3 RPC API as documented at:
https://developers.neo.org/docs/n3/reference/rpc/api

The provider handles:
- Address validation and conversion (using local wallet utils)
- Network-specific API endpoints
- Direct RPC method calls for Neo N3
"""

import json
from typing import Dict, Any, List, Optional
from neo3.api import NeoRpcClient
from neo3.core import types
from neo3.wallet import utils

# RPC URLs for different networks
MAINNET_RPC = "https://mainnet1.neo.coz.io:443"
TESTNET_RPC = "https://testnet2.neo.coz.io:443"


class Neo3Provider:
    """Neo N3 blockchain data provider using neo-mamba library

    This class provides a unified interface for querying Neo N3 blockchain data
    using only methods that are officially available in the Neo N3 RPC API.

    Attributes:
        network (str): The Neo network to connect to ('mainnet' or 'testnet')
        rpc_client (NeoRpcClient): The neo-mamba RPC client for blockchain interaction
    """

    def __init__(self, network: str = "testnet"):
        """Initialize the Neo N3 provider

        Args:
            network (str): The Neo network to connect to. Must be 'mainnet' or 'testnet'

        Raises:
            ValueError: If network is not 'mainnet' or 'testnet'
        """
        if network not in ["mainnet", "testnet"]:
            raise ValueError("Network must be 'mainnet' or 'testnet'")

        self.network = network
        rpc_url = MAINNET_RPC if network == "mainnet" else TESTNET_RPC

        # Initialize neo-mamba RPC client
        self.rpc_client = NeoRpcClient(rpc_url)

    def _validate_address(self, address: str) -> types.UInt160:
        """Validate and convert address format

        Converts Neo addresses to script hash format if they are in standard format.
        If the address is already in script hash format, it returns as is.
        Uses local validation with wallet utils (no RPC call needed).

        Args:
            address (str): The address to validate and convert

        Returns:
            types.UInt160: The address as UInt160 script hash

        Raises:
            ValueError: If the address is not a valid Neo address
        """
        try:
            # Try to parse as script hash first
            if address.startswith("0x"):
                return types.UInt160.from_string(address[2:])
            else:
                return types.UInt160.from_string(address)
        except:
            # If that fails, try to convert from standard address format
            try:
                # Use local validation with wallet utils
                if utils.is_valid_address(address):
                    # Convert the address string to script hash
                    return utils.address_to_script_hash(address)
                else:
                    raise ValueError(f"Invalid Neo address: {address}")
            except Exception as e:
                raise ValueError(f"Invalid Neo address: {address}")

    async def _make_request(self, method: str, params: Dict[str, Any]) -> Any:
        """Make a generic RPC request to the Neo N3 node

        Args:
            method (str): The RPC method name (e.g., "getblockcount", "getnep17balances")
            params (Dict[str, Any]): Parameters for the RPC method

        Returns:
            Any: The result from the RPC call

        Raises:
            Exception: If the RPC call fails
        """
        # Convert method name to lowercase (Neo RPC convention)
        rpc_method_name = method.lower()
        
        # Prepare params as a list (Neo RPC format)
        rpc_params = []
        if params:
            # For single param methods, pass as single element list
            # For multiple params, convert dict to list of values
            if len(params) == 1:
                rpc_params = [list(params.values())[0]]
            else:
                # For methods with multiple params, pass as list
                rpc_params = list(params.values()) if isinstance(params, dict) else params
        
        if hasattr(self.rpc_client, '_do_post'):
            try:
                result = await self.rpc_client._do_post(rpc_method_name, rpc_params)
                return result
            except Exception as e:
                raise Exception(f"Error making RPC request {method}: {str(e)}")
        
        raise Exception(f"RPC method {method} not supported")

    def _handle_response(self, result: Any) -> Any:
        """Handle neo-mamba response and extract result

        Args:
            result: The result from neo-mamba RPC call

        Returns:
            Any: The processed result data

        Raises:
            Exception: If the response contains an error
        """
        if result is None:
            raise Exception("Empty response from Neo RPC")

        return result

    async def close(self):
        """Close the RPC client connection"""
        if hasattr(self.rpc_client, 'close'):
            await self.rpc_client.close()

    # Blockchain methods (from official Neo N3 RPC API)
    
    async def get_best_block_hash(self) -> str:
        """Get the hash of the latest block in the blockchain
        
        Returns:
            str: The hash of the latest block (as hex string)
        """
        try:
            result = await self.rpc_client.get_best_block_hash()
            # Convert UInt256 to string
            if isinstance(result, types.UInt256):
                return str(result)
            return str(self._handle_response(result))
        except Exception as e:
            raise Exception(f"Failed to get best block hash: {str(e)}")

    async def get_block(self, hash_or_index: str, verbose: int = 0) -> Dict[str, Any]:
        """Get block information by hash or index
        
        Args:
            hash_or_index (str): Block hash or block index
            verbose (int): Verbose level (0 or 1)
        
        Returns:
            Dict[str, Any]: Block information
        """
        try:
            # Try to parse as index first
            try:
                index = int(hash_or_index)
                block = await self.rpc_client.get_block(index)
            except ValueError:
                # It's a hash
                block_hash = types.UInt256.from_string(hash_or_index)
                block = await self.rpc_client.get_block(block_hash)
            return self._handle_response(block)
        except Exception as e:
            raise Exception(f"Failed to get block: {str(e)}")

    async def get_block_count(self) -> int:
        """Get the block count of the blockchain
        
        Returns:
            int: Total number of blocks
        """
        try:
            count = await self.rpc_client.get_block_count()
            return self._handle_response(count)
        except Exception as e:
            raise Exception(f"Failed to get block count: {str(e)}")

    async def get_block_hash(self, index: int) -> str:
        """Get block hash by index
        
        Args:
            index (int): Block index
        
        Returns:
            str: Block hash (as hex string)
        """
        try:
            result = await self.rpc_client.get_block_hash(index)
            # Convert UInt256 to string
            if isinstance(result, types.UInt256):
                return str(result)
            return str(self._handle_response(result))
        except Exception as e:
            raise Exception(f"Failed to get block hash: {str(e)}")

    async def get_block_header(self, hash_or_index: str, verbose: int = 0) -> Dict[str, Any]:
        """Get block header information
        
        Args:
            hash_or_index (str): Block hash or block index
            verbose (int): Verbose level (0 or 1)
        
        Returns:
            Dict[str, Any]: Block header information
        """
        try:
            # Try to parse as index first
            try:
                index = int(hash_or_index)
                header = await self.rpc_client.get_block_header(index)
            except ValueError:
                # It's a hash
                block_hash = types.UInt256.from_string(hash_or_index)
                header = await self.rpc_client.get_block_header(block_hash)
            return self._handle_response(header)
        except Exception as e:
            raise Exception(f"Failed to get block header: {str(e)}")

    async def get_committee(self) -> List[str]:
        """Get the public key list of current Neo committee members
        
        Returns:
            List[str]: List of committee member public keys
        """
        try:
            # Use _do_post directly as neo-mamba may not have this method
            result = await self.rpc_client._do_post("getcommittee", [])
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get committee: {str(e)}")

    async def get_native_contracts(self) -> List[Dict[str, Any]]:
        """Get the list of native contracts
        
        Returns:
            List[Dict[str, Any]]: List of native contracts
        """
        try:
            # Use _do_post directly as neo-mamba may not have this method
            result = await self.rpc_client._do_post("getnativecontracts", [])
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get native contracts: {str(e)}")

    async def get_next_block_validators(self) -> List[Dict[str, Any]]:
        """Get the validators list of the next block
        
        Returns:
            List[Dict[str, Any]]: List of validators
        """
        try:
            # Use _do_post directly as neo-mamba may not have this method
            result = await self.rpc_client._do_post("getnextblockvalidators", [])
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get next block validators: {str(e)}")

    async def get_contract_state(self, script_hash: str) -> Dict[str, Any]:
        """Get contract state information
        
        Args:
            script_hash (str): Contract script hash
        
        Returns:
            Dict[str, Any]: Contract state information
        """
        try:
            contract_hash = types.UInt160.from_string(script_hash)
            result = await self.rpc_client.get_contract_state(contract_hash)
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get contract state: {str(e)}")

    async def get_raw_mempool(self, should_get_unverified: int = 0) -> List[str]:
        """Get list of transactions in memory pool
        
        Args:
            should_get_unverified (int): If 1, get all transactions including unverified
        
        Returns:
            List[str] or Dict: List of transaction hashes (if should_get_unverified=0),
                              or Dict with verified/unverified (if should_get_unverified=1)
        """
        try:
            # neo-mamba's get_raw_mempool() doesn't take parameters
            # If we need unverified transactions, use _do_post directly
            if should_get_unverified:
                # Call RPC directly with parameter
                result = await self.rpc_client._do_post("getrawmempool", [should_get_unverified])
            else:
                # Use neo-mamba's method for default behavior (verified only)
                result = await self.rpc_client.get_raw_mempool()
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get raw mempool: {str(e)}")

    async def get_raw_transaction(self, txid: str, verbose: int = 0) -> Dict[str, Any]:
        """Get transaction information by hash
        
        Args:
            txid (str): Transaction hash
            verbose (int): Verbose level (0 or 1)
        
        Returns:
            Dict[str, Any]: Transaction information
        """
        try:
            tx_hash = types.UInt256.from_string(txid)
            result = await self.rpc_client.get_transaction(tx_hash, verbose)
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get raw transaction: {str(e)}")

    async def get_storage(self, script_hash: str, key: str) -> str:
        """Get storage value by contract script hash and key
        
        Args:
            script_hash (str): Contract script hash
            key (str): Storage key
        
        Returns:
            str: Storage value
        """
        try:
            contract_hash = types.UInt160.from_string(script_hash)
            result = await self.rpc_client.get_storage(contract_hash, key)
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get storage: {str(e)}")

    async def get_transaction_height(self, txid: str) -> int:
        """Get transaction height by transaction hash
        
        Args:
            txid (str): Transaction hash
        
        Returns:
            int: Transaction height
        """
        try:
            tx_hash = types.UInt256.from_string(txid)
            result = await self.rpc_client.get_transaction_height(tx_hash)
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get transaction height: {str(e)}")

    # Node methods

    async def get_connection_count(self) -> int:
        """Get the current connection count of the node
        
        Returns:
            int: Connection count
        """
        try:
            result = await self.rpc_client.get_connection_count()
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get connection count: {str(e)}")

    async def get_peers(self) -> Dict[str, Any]:
        """Get list of nodes that are currently connected/disconnected
        
        Returns:
            Dict[str, Any]: Peer information
        """
        try:
            result = await self.rpc_client.get_peers()
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get peers: {str(e)}")

    async def get_version(self) -> Dict[str, Any]:
        """Get the version information of the node
        
        Returns:
            Dict[str, Any]: Version information
        """
        try:
            result = await self.rpc_client.get_version()
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get version: {str(e)}")

    # Smart Contract methods

    async def get_unclaimed_gas(self, address: str) -> str:
        """Get unclaimed gas of the specified address
        
        Args:
            address (str): Neo address
        
        Returns:
            str: Unclaimed gas amount
        """
        try:
            result = await self.rpc_client.get_unclaimed_gas(address)
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get unclaimed gas: {str(e)}")

    async def invoke_function(
        self,
        script_hash: str,
        operation: str,
        params: List[Any] = None,
        sender: str = None,
        signers: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Invoke a smart contract function
        
        Args:
            script_hash (str): Contract script hash
            operation (str): Function name
            params (List[Any]): Function parameters
            sender (str): Sender address (optional)
            signers (List[Dict[str, Any]]): Signers (optional)
        
        Returns:
            Dict[str, Any]: Invocation result
        """
        try:
            contract_hash = types.UInt160.from_string(script_hash)
            result = await self.rpc_client.invoke_function(
                contract_hash,
                operation,
                params or [],
                sender,
                signers or []
            )
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to invoke function: {str(e)}")

    # TokensTracker plugin methods

    async def get_nep11_balances(self, address: str) -> Dict[str, Any]:
        """Get NEP-11 token balances for an address
        
        Args:
            address (str): Neo address
        
        Returns:
            Dict[str, Any]: NEP-11 balances
        """
        try:
            # Use _do_post directly as neo-mamba may not have this method
            result = await self.rpc_client._do_post("getnep11balances", [address])
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get NEP-11 balances: {str(e)}")

    async def get_nep11_properties(self, contract_hash: str, token_id: str) -> Dict[str, Any]:
        """Get NEP-11 token properties
        
        Args:
            contract_hash (str): Contract script hash
            token_id (str): Token ID
        
        Returns:
            Dict[str, Any]: Token properties
        """
        try:
            # Use _do_post directly as neo-mamba may not have this method
            # Remove 0x prefix if present
            contract_hash_clean = contract_hash[2:] if contract_hash.startswith("0x") else contract_hash
            result = await self.rpc_client._do_post("getnep11properties", [contract_hash_clean, token_id])
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get NEP-11 properties: {str(e)}")

    async def get_nep11_transfers(self, address: str, timestamp: int = None) -> Dict[str, Any]:
        """Get NEP-11 transfers for an address
        
        Args:
            address (str): Neo address
            timestamp (int): Optional timestamp filter
        
        Returns:
            Dict[str, Any]: NEP-11 transfers
        """
        try:
            # Use _do_post directly as neo-mamba may not have this method
            params = [address]
            if timestamp:
                params.append(timestamp)
            result = await self.rpc_client._do_post("getnep11transfers", params)
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get NEP-11 transfers: {str(e)}")

    async def get_nep17_balances(self, address: str) -> Dict[str, Any]:
        """Get NEP-17 token balances for an address
        
        Args:
            address (str): Neo address
        
        Returns:
            Dict[str, Any]: NEP-17 balances
        """
        try:
            result = await self.rpc_client.get_nep17_balances(address)
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get NEP-17 balances: {str(e)}")

    async def get_nep17_transfers(self, address: str, timestamp: int = None) -> Dict[str, Any]:
        """Get NEP-17 transfers for an address
        
        Args:
            address (str): Neo address
            timestamp (int): Optional timestamp filter (Unix timestamp in milliseconds)
        
        Returns:
            Dict[str, Any]: NEP-17 transfers
        """
        try:
            # Always use _do_post to have consistent parameter handling
            # According to Neo RPC API, getnep17transfers takes [address] or [address, timestamp]
            params = [address]
            if timestamp is not None:
                params.append(timestamp)
            result = await self.rpc_client._do_post("getnep17transfers", params)
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get NEP-17 transfers: {str(e)}")

    # ApplicationLogs plugin methods

    async def get_application_log(self, txid: str) -> Dict[str, Any]:
        """Get application log for a transaction
        
        Args:
            txid (str): Transaction hash
        
        Returns:
            Dict[str, Any]: Application log
        """
        try:
            tx_hash = types.UInt256.from_string(txid)
            result = await self.rpc_client.get_application_log(tx_hash)
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get application log: {str(e)}")

    # StateService plugin methods

    async def get_state_root(self, index: int) -> Dict[str, Any]:
        """Get state root by block height
        
        Args:
            index (int): Block height
        
        Returns:
            Dict[str, Any]: State root information
        """
        try:
            result = await self._make_request("getstateroot", {"index": index})
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get state root: {str(e)}")

    async def get_state_height(self) -> int:
        """Get state root height
        
        Returns:
            int: State root height
        """
        try:
            result = await self._make_request("getstateheight", {})
            return self._handle_response(result)
        except Exception as e:
            raise Exception(f"Failed to get state height: {str(e)}")

    def validate_address(self, address: str) -> bool:
        """Validate a Neo address (using local validation)
        
        Args:
            address (str): Neo address to validate
        
        Returns:
            bool: True if address is valid
        """
        try:
            self._validate_address(address)
            return True
        except:
            return False

