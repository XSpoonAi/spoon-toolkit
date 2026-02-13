"""Neo governance action tools.

Provides tools for governance operations on the Neo N3 blockchain:
- Claiming unclaimed GAS
- Voting for consensus node candidates
"""

import logging
from typing import Optional

from pydantic import Field

from spoon_ai.tools.base import BaseTool, ToolResult
from .transfer_tools import (
    _get_rpc_url,
    _resolve_private_key,
    _create_neo3_account,
)

logger = logging.getLogger(__name__)


class NeoClaimGasTool(BaseTool):
    """Claim unclaimed GAS on the Neo N3 blockchain.

    On Neo N3, GAS is automatically distributed to NEO holders. Unclaimed GAS
    is collected by transferring NEO to yourself, which triggers the GAS distribution.
    This tool checks unclaimed GAS and triggers the claim if there is any.
    """

    name: str = "neo_claim_gas"
    description: str = (
        "Claim unclaimed GAS on the Neo N3 blockchain. "
        "NEO holders earn GAS over time. This tool checks how much unclaimed GAS "
        "the account has and triggers the claim by sending a self-transfer of NEO. "
        "Returns the amount of GAS claimed and the transaction details."
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
            "private_key": {
                "type": "string",
                "description": "Private key (WIF or hex). If omitted, uses NEO_PRIVATE_KEY env var.",
            },
        },
        "required": [],
    }

    network: str = Field(default="testnet")
    private_key: Optional[str] = Field(default=None)

    async def execute(
        self,
        network: Optional[str] = None,
        private_key: Optional[str] = None,
    ) -> ToolResult:
        try:
            network = network or self.network or "testnet"
            private_key = private_key or self.private_key

            try:
                key = _resolve_private_key(private_key)
            except ValueError as e:
                return ToolResult(error=str(e))

            try:
                account = _create_neo3_account(key)
            except Exception as e:
                return ToolResult(error=f"Failed to create account from private key: {e}")

            from neo3.api.wrappers import ChainFacade, NeoToken
            from neo3.api.helpers.signing import sign_with_account
            from neo3.network.payloads.verification import Signer

            rpc_url = _get_rpc_url(network)
            facade = ChainFacade(rpc_host=rpc_url)
            facade.add_signer(
                sign_with_account(account),
                Signer(account.script_hash),
            )

            neo_token = NeoToken()
            source_address = str(account.address)

            # Check unclaimed GAS
            unclaimed_receipt = await facade.test_invoke(
                neo_token.get_unclaimed_gas(account.script_hash)
            )
            unclaimed_raw = unclaimed_receipt.result
            unclaimed_gas = unclaimed_raw / 10**8  # GAS has 8 decimals

            if unclaimed_raw == 0:
                return ToolResult(output={
                    "address": source_address,
                    "unclaimed_gas": 0.0,
                    "message": "No unclaimed GAS to claim",
                    "network": network,
                })

            # Check NEO balance for self-transfer
            neo_balance_receipt = await facade.test_invoke(
                neo_token.balance_of(account.script_hash)
            )
            neo_balance = neo_balance_receipt.result

            if neo_balance == 0:
                return ToolResult(output={
                    "address": source_address,
                    "unclaimed_gas": unclaimed_gas,
                    "message": "Account holds 0 NEO; cannot trigger GAS claim via self-transfer",
                    "network": network,
                })

            # Transfer NEO to self to trigger GAS claim
            transfer_call = neo_token.transfer(
                source=account.script_hash,
                destination=source_address,
                amount=neo_balance,
            )

            receipt = await facade.invoke(transfer_call)
            state_str = "HALT" if "HALT" in str(receipt.state) else str(receipt.state)
            success = "HALT" in state_str

            result = {
                "tx_hash": str(receipt.tx_hash),
                "success": success,
                "state": state_str,
                "address": source_address,
                "unclaimed_gas": unclaimed_gas,
                "neo_balance": neo_balance,
                "gas_consumed_by_tx": receipt.gas_consumed,
                "included_in_block": receipt.included_in_block,
                "network": network,
            }

            if receipt.exception:
                result["exception"] = receipt.exception

            if not success:
                return ToolResult(error=f"GAS claim failed: {receipt.exception or state_str}", output=result)

            return ToolResult(output=result)

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoClaimGasTool error: {err_msg}")
            return ToolResult(error=f"GAS claim failed: {err_msg}")


class NeoVoteTool(BaseTool):
    """Vote for a consensus node candidate on the Neo N3 blockchain.

    Cast a vote using your NEO holdings for a candidate to become a consensus node.
    Your entire NEO balance counts as votes. You can change your vote at any time.
    """

    name: str = "neo_vote"
    description: str = (
        "Vote for a consensus node candidate on the Neo N3 blockchain. "
        "Useful when you want to participate in Neo governance by voting for "
        "a consensus node candidate. Your full NEO balance counts as votes. "
        "Returns transaction hash and vote status."
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
            "candidate_pubkey": {
                "type": "string",
                "description": "Public key of the candidate to vote for (hex-encoded, e.g. 02...)",
            },
            "private_key": {
                "type": "string",
                "description": "Voter private key (WIF or hex). If omitted, uses NEO_PRIVATE_KEY env var.",
            },
        },
        "required": ["candidate_pubkey"],
    }

    network: str = Field(default="testnet")
    candidate_pubkey: Optional[str] = Field(default=None)
    private_key: Optional[str] = Field(default=None)

    async def execute(
        self,
        candidate_pubkey: Optional[str] = None,
        network: Optional[str] = None,
        private_key: Optional[str] = None,
    ) -> ToolResult:
        try:
            network = network or self.network or "testnet"
            candidate_pubkey = candidate_pubkey or self.candidate_pubkey
            private_key = private_key or self.private_key

            if not candidate_pubkey:
                return ToolResult(error="Missing candidate_pubkey parameter")

            try:
                key = _resolve_private_key(private_key)
            except ValueError as e:
                return ToolResult(error=str(e))

            try:
                account = _create_neo3_account(key)
            except Exception as e:
                return ToolResult(error=f"Failed to create account from private key: {e}")

            from neo3.api.wrappers import ChainFacade, NeoToken
            from neo3.api.helpers.signing import sign_with_account
            from neo3.network.payloads.verification import Signer
            from neo3.core import cryptography

            rpc_url = _get_rpc_url(network)
            facade = ChainFacade(rpc_host=rpc_url)
            facade.add_signer(
                sign_with_account(account),
                Signer(account.script_hash),
            )

            neo_token = NeoToken()
            source_address = str(account.address)

            # Parse candidate public key
            pubkey_hex = candidate_pubkey
            if pubkey_hex.startswith("0x"):
                pubkey_hex = pubkey_hex[2:]
            candidate_key = cryptography.ECPoint.deserialize_from_bytes(
                bytes.fromhex(pubkey_hex)
            )

            # Cast vote
            vote_call = neo_token.candidate_vote(
                voter=account.script_hash,
                candidate=candidate_key,
            )

            receipt = await facade.invoke(vote_call)
            state_str = "HALT" if "HALT" in str(receipt.state) else str(receipt.state)
            success = "HALT" in state_str

            result = {
                "tx_hash": str(receipt.tx_hash),
                "success": success,
                "state": state_str,
                "voter": source_address,
                "candidate": candidate_pubkey,
                "gas_consumed": receipt.gas_consumed,
                "included_in_block": receipt.included_in_block,
                "network": network,
            }

            if receipt.exception:
                result["exception"] = receipt.exception

            if not success:
                return ToolResult(error=f"Vote failed: {receipt.exception or state_str}", output=result)

            return ToolResult(output=result)

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoVoteTool error: {err_msg}")
            return ToolResult(error=f"Vote failed: {err_msg}")
