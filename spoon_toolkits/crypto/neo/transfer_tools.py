"""Neo token transfer tools.

Supports transferring NEP-17 tokens (NEO, GAS, custom) and NEP-11 NFTs
on the Neo N3 blockchain. Uses neo-mamba's ChainFacade for transaction
building, signing, fee calculation, and broadcasting.
"""

import os
import logging
from typing import Optional

from pydantic import Field

from spoon_ai.tools.base import BaseTool, ToolResult
from .signers import (
    ENV_PRIVATE_KEY,
    _is_encrypted,
    _get_private_key_from_vault,
)

logger = logging.getLogger(__name__)


# RPC URLs (same convention as neo_provider.py)
DEFAULT_MAINNET_RPC = "https://mainmagnet.ngd.network:443"
DEFAULT_TESTNET_RPC = "https://testmagnet.ngd.network:443"

# Well-known token identifiers
_TOKEN_ALIASES = {"NEO", "GAS"}


def _get_rpc_url(network: str) -> str:
    """Resolve RPC URL from network name and environment variables."""
    if network == "mainnet":
        return os.getenv("NEO_MAINNET_RPC", DEFAULT_MAINNET_RPC)
    return os.getenv("NEO_TESTNET_RPC", DEFAULT_TESTNET_RPC)


def _resolve_private_key(private_key: Optional[str] = None) -> str:
    """Resolve private key from parameter, env var, or vault.

    Priority: explicit param → plain env → vault-decrypted env.

    Returns:
        Private key string (WIF or hex).

    Raises:
        ValueError: if no private key can be resolved.
    """
    if private_key:
        return private_key.strip()

    env_key = os.getenv(ENV_PRIVATE_KEY)
    if env_key and not _is_encrypted(env_key):
        return env_key.strip()

    vault_key = _get_private_key_from_vault()
    if vault_key:
        return vault_key.strip()

    raise ValueError(
        f"No private key available. Provide private_key parameter or set {ENV_PRIVATE_KEY} env var."
    )


def _create_neo3_account(private_key: str):
    """Create a neo3 Account from a WIF or hex private key.

    Returns:
        neo3.wallet.account.Account instance.
    """
    from neo3.wallet.account import Account

    # Try WIF first
    try:
        return Account.from_wif(private_key)
    except Exception:
        pass

    # Try hex private key
    key_hex = private_key
    if key_hex.startswith("0x"):
        key_hex = key_hex[2:]
    key_bytes = bytes.fromhex(key_hex)
    return Account.from_private_key(key_bytes)


class NeoTransferTool(BaseTool):
    """Transfer NEP-17 tokens (NEO, GAS, or custom tokens) on the Neo N3 blockchain.

    Builds, signs, and broadcasts a transfer transaction using neo-mamba's ChainFacade.
    Supports both local private key and environment-variable-based signing.
    """

    name: str = "neo_transfer"
    description: str = (
        "Transfer NEP-17 tokens (NEO, GAS, or custom tokens) on the Neo N3 blockchain. "
        "Useful when you need to send NEO, GAS, or any NEP-17 token to another address. "
        "Returns transaction hash, execution state, gas consumed, and block information."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "network": {
                "type": "string",
                "enum": ["mainnet", "testnet"],
                "description": "Neo network to use",
                "default": "testnet",
            },
            "to_address": {
                "type": "string",
                "description": "Recipient Neo address (Base58 format, e.g. NXV2zshzasps7nqz2kcrv69zWhksVSG87D)",
            },
            "amount": {
                "type": "string",
                "description": "Amount to transfer in human-readable units (e.g. '10', '0.5')",
            },
            "token": {
                "type": "string",
                "description": "Token to transfer: 'NEO', 'GAS', or a contract hash (0x-prefixed). Defaults to GAS.",
                "default": "GAS",
            },
            "private_key": {
                "type": "string",
                "description": "Sender private key (WIF or hex). If omitted, uses NEO_PRIVATE_KEY env var.",
            },
            "wait_for_receipt": {
                "type": "boolean",
                "description": "Whether to wait for the transaction to be included in a block. Default true.",
                "default": True,
            },
        },
        "required": ["to_address", "amount"],
    }

    network: str = Field(default="testnet")
    to_address: Optional[str] = Field(default=None)
    amount: Optional[str] = Field(default=None)
    token: str = Field(default="GAS")
    private_key: Optional[str] = Field(default=None)
    wait_for_receipt: bool = Field(default=True)

    async def execute(
        self,
        to_address: Optional[str] = None,
        amount: Optional[str] = None,
        token: Optional[str] = None,
        network: Optional[str] = None,
        private_key: Optional[str] = None,
        wait_for_receipt: Optional[bool] = None,
    ) -> ToolResult:
        try:
            # Resolve parameters
            network = network or self.network or "testnet"
            to_address = to_address or self.to_address
            amount = amount or self.amount
            token = token or self.token or "GAS"
            private_key = private_key or self.private_key
            wait_for_receipt = wait_for_receipt if wait_for_receipt is not None else self.wait_for_receipt

            if not to_address:
                return ToolResult(error="Missing to_address parameter")
            if not amount:
                return ToolResult(error="Missing amount parameter")

            try:
                amount_float = float(amount)
            except ValueError:
                return ToolResult(error=f"Invalid amount: {amount}")

            if amount_float <= 0:
                return ToolResult(error="Amount must be positive")

            # Resolve private key and create account
            try:
                key = _resolve_private_key(private_key)
            except ValueError as e:
                return ToolResult(error=str(e))

            try:
                account = _create_neo3_account(key)
            except Exception as e:
                return ToolResult(error=f"Failed to create account from private key: {e}")

            # Lazy imports for neo3
            from neo3.api.wrappers import (
                ChainFacade,
                NEP17Contract,
                NeoToken,
                GasToken,
            )
            from neo3.api.helpers.signing import sign_with_account
            from neo3.network.payloads.verification import Signer
            from neo3.core import types

            # Setup facade
            rpc_url = _get_rpc_url(network)
            facade = ChainFacade(rpc_host=rpc_url)
            facade.add_signer(
                sign_with_account(account),
                Signer(account.script_hash),
            )

            # Resolve token contract
            token_upper = token.upper()
            if token_upper == "NEO":
                token_contract = NeoToken()
                decimals = 0
            elif token_upper == "GAS":
                token_contract = GasToken()
                decimals = 8
            else:
                # Custom NEP-17 token by contract hash
                contract_hash = token
                if not contract_hash.startswith("0x"):
                    contract_hash = f"0x{contract_hash}"
                token_contract = NEP17Contract(types.UInt160.from_string(contract_hash))
                # Query decimals from contract
                decimals_receipt = await facade.test_invoke(token_contract.decimals())
                decimals = decimals_receipt.result

            # For NEO (0 decimals), amount must be integer
            if decimals == 0:
                if amount_float != int(amount_float):
                    return ToolResult(error="NEO is indivisible; amount must be a whole number")
                transfer_call = token_contract.transfer(
                    source=account.script_hash,
                    destination=to_address,
                    amount=int(amount_float),
                )
            else:
                transfer_call = token_contract.transfer_friendly(
                    source=account.script_hash,
                    destination=to_address,
                    amount=amount_float,
                    decimals=decimals,
                )

            # Execute transaction
            source_address = str(account.address)

            if wait_for_receipt:
                receipt = await facade.invoke(transfer_call)
                state_str = "HALT" if str(receipt.state) == "VMState.HALT" or "HALT" in str(receipt.state) else str(receipt.state)
                success = "HALT" in state_str

                result = {
                    "tx_hash": str(receipt.tx_hash),
                    "success": success,
                    "state": state_str,
                    "gas_consumed": receipt.gas_consumed,
                    "included_in_block": receipt.included_in_block,
                    "confirmations": receipt.confirmations,
                    "from": source_address,
                    "to": to_address,
                    "amount": amount,
                    "token": token,
                    "network": network,
                }

                if receipt.exception:
                    result["exception"] = receipt.exception

                if not success:
                    return ToolResult(error=f"Transaction failed: {receipt.exception or state_str}", output=result)

                return ToolResult(output=result)
            else:
                tx_hash = await facade.invoke_fast(transfer_call)
                return ToolResult(output={
                    "tx_hash": str(tx_hash),
                    "status": "submitted",
                    "from": source_address,
                    "to": to_address,
                    "amount": amount,
                    "token": token,
                    "network": network,
                })

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoTransferTool error: {err_msg}")
            return ToolResult(error=f"Transfer failed: {err_msg}")


class NeoNep11TransferTool(BaseTool):
    """Transfer a non-divisible NFT (NEP-11) on the Neo N3 blockchain.

    Transfers ownership of an NFT token to a destination address.
    The sender must be the current owner of the token.
    """

    name: str = "neo_nep11_transfer"
    description: str = (
        "Transfer a non-divisible NFT (NEP-11 standard) on the Neo N3 blockchain. "
        "Useful when you need to send an NFT to another address. "
        "The sender must own the token. Returns transaction hash and status."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "network": {
                "type": "string",
                "enum": ["mainnet", "testnet"],
                "description": "Neo network to use",
                "default": "testnet",
            },
            "contract_hash": {
                "type": "string",
                "description": "NEP-11 NFT contract hash (0x-prefixed)",
            },
            "to_address": {
                "type": "string",
                "description": "Recipient Neo address",
            },
            "token_id": {
                "type": "string",
                "description": "Token ID to transfer (hex-encoded bytes or UTF-8 string)",
            },
            "private_key": {
                "type": "string",
                "description": "Sender private key (WIF or hex). If omitted, uses NEO_PRIVATE_KEY env var.",
            },
        },
        "required": ["contract_hash", "to_address", "token_id"],
    }

    network: str = Field(default="testnet")
    contract_hash: Optional[str] = Field(default=None)
    to_address: Optional[str] = Field(default=None)
    token_id: Optional[str] = Field(default=None)
    private_key: Optional[str] = Field(default=None)

    async def execute(
        self,
        contract_hash: Optional[str] = None,
        to_address: Optional[str] = None,
        token_id: Optional[str] = None,
        network: Optional[str] = None,
        private_key: Optional[str] = None,
    ) -> ToolResult:
        try:
            network = network or self.network or "testnet"
            contract_hash = contract_hash or self.contract_hash
            to_address = to_address or self.to_address
            token_id = token_id or self.token_id
            private_key = private_key or self.private_key

            if not contract_hash:
                return ToolResult(error="Missing contract_hash parameter")
            if not to_address:
                return ToolResult(error="Missing to_address parameter")
            if not token_id:
                return ToolResult(error="Missing token_id parameter")

            try:
                key = _resolve_private_key(private_key)
            except ValueError as e:
                return ToolResult(error=str(e))

            try:
                account = _create_neo3_account(key)
            except Exception as e:
                return ToolResult(error=f"Failed to create account from private key: {e}")

            from neo3.api.wrappers import ChainFacade, NEP11NonDivisibleContract
            from neo3.api.helpers.signing import sign_with_account
            from neo3.network.payloads.verification import Signer
            from neo3.core import types

            rpc_url = _get_rpc_url(network)
            facade = ChainFacade(rpc_host=rpc_url)
            facade.add_signer(
                sign_with_account(account),
                Signer(account.script_hash),
            )

            if not contract_hash.startswith("0x"):
                contract_hash = f"0x{contract_hash}"
            nft_contract = NEP11NonDivisibleContract(
                types.UInt160.from_string(contract_hash)
            )

            # Parse token_id: try hex first, fall back to UTF-8 encoding
            try:
                tid_hex = token_id
                if tid_hex.startswith("0x"):
                    tid_hex = tid_hex[2:]
                token_id_bytes = bytes.fromhex(tid_hex)
            except ValueError:
                token_id_bytes = token_id.encode("utf-8")

            transfer_call = nft_contract.transfer(
                destination=to_address,
                token_id=token_id_bytes,
            )

            source_address = str(account.address)
            receipt = await facade.invoke(transfer_call)
            state_str = "HALT" if "HALT" in str(receipt.state) else str(receipt.state)
            success = "HALT" in state_str

            result = {
                "tx_hash": str(receipt.tx_hash),
                "success": success,
                "state": state_str,
                "gas_consumed": receipt.gas_consumed,
                "included_in_block": receipt.included_in_block,
                "from": source_address,
                "to": to_address,
                "contract": contract_hash,
                "token_id": token_id,
                "network": network,
            }

            if receipt.exception:
                result["exception"] = receipt.exception

            if not success:
                return ToolResult(error=f"NFT transfer failed: {receipt.exception or state_str}", output=result)

            return ToolResult(output=result)

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoNep11TransferTool error: {err_msg}")
            return ToolResult(error=f"NFT transfer failed: {err_msg}")
