import logging
from typing import Optional
from pydantic import Field

from spoon_ai.tools.base import BaseTool, ToolResult
from .service import get_rpc_url, get_associated_token_address, is_native_sol
from .signers import SignerManager, SolanaSigner
from .constants import TOKEN_PROGRAM_ID

from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction
from solders.message import MessageV0
from solders.system_program import transfer as system_transfer

from spl.token.instructions import transfer, create_associated_token_account

logger = logging.getLogger(__name__)


class SolanaTransferTool(BaseTool):
    """Transfer SOL or SPL tokens on Solana.

    Supports both local private key and Turnkey secure signing.
    """

    name: str = "solana_transfer"
    description: str = "Transfer SOL or SPL tokens to another address on Solana. Supports local and Turnkey secure signing."
    parameters: dict = {
        "type": "object",
        "properties": {
            "rpc_url": {
                "type": "string",
                "description": "Solana RPC endpoint URL. Defaults to SOLANA_RPC_URL env var."
            },
            "signer_type": {
                "type": "string",
                "enum": ["local", "turnkey", "auto"],
                "description": "Signing method: 'local' (private key), 'turnkey' (secure API), or 'auto' (detect from env)",
                "default": "auto",
            },
            "private_key": {
                "type": "string",
                "description": "Sender private key. Required for local signing. Defaults to SOLANA_PRIVATE_KEY env var."
            },
            "turnkey_sign_with": {
                "type": "string",
                "description": "Turnkey signing identity (Solana address). Required for Turnkey signing. Defaults to TURNKEY_SOLANA_ADDRESS env var.",
            },
            "recipient": {
                "type": "string",
                "description": "Recipient Solana address"
            },
            "amount": {
                "type": "number",
                "description": "Amount to transfer (in human-readable units)"
            },
            "token_address": {
                "type": "string",
                "description": "SPL token mint address. If null/omitted, transfers SOL."
            }
        },
        "required": ["recipient", "amount"],
    }

    rpc_url: Optional[str] = Field(default=None)
    signer_type: str = Field(default="auto")
    private_key: Optional[str] = Field(default=None)
    turnkey_sign_with: Optional[str] = Field(default=None)
    recipient: Optional[str] = Field(default=None)
    amount: Optional[str] = Field(default=None)
    token_address: Optional[str] = Field(default=None)

    async def execute(
        self,
        rpc_url: Optional[str] = None,
        signer_type: Optional[str] = None,
        private_key: Optional[str] = None,
        turnkey_sign_with: Optional[str] = None,
        recipient: Optional[str] = None,
        amount: Optional[str] = None,
        token_address: Optional[str] = None
    ) -> ToolResult:
        """Execute transfer operation."""
        try:
            # Resolve parameters
            rpc_url = rpc_url or self.rpc_url or get_rpc_url()
            signer_type = signer_type or self.signer_type
            private_key = private_key or self.private_key
            turnkey_sign_with = turnkey_sign_with or self.turnkey_sign_with
            recipient = recipient or self.recipient
            amount = amount or self.amount
            token_address = token_address or self.token_address
            if token_address == "null":
                token_address = None
            is_native = is_native_sol(token_address)

            if not recipient:
                return ToolResult(error="Recipient address is required")
            if amount is None:
                return ToolResult(error="Amount is required")
            amount_float = float(amount)
            display_amount = amount

            # Create signer using SignerManager (supports local and Turnkey)
            try:
                signer = SignerManager.create_signer(
                    signer_type=signer_type,
                    private_key=private_key,
                    turnkey_sign_with=turnkey_sign_with,
                )
            except Exception as e:
                return ToolResult(error=f"Failed to create signer: {str(e)}")

            # Execute transfer
            if is_native:
                result = await self._transfer_sol(
                    rpc_url, signer, recipient, amount_float, display_amount
                )
            else:
                result = await self._transfer_spl_token(
                    rpc_url, signer, recipient, amount_float,
                    token_address, display_amount
                )

            return result

        except Exception as e:
            logger.error(f"SolanaTransferTool error: {e}")
            return ToolResult(error=f"Transfer failed: {str(e)}")

    async def _transfer_sol(
        self,
        rpc_url: str,
        signer: SolanaSigner,
        recipient: str,
        amount: float,
        display_amount
    ) -> ToolResult:
        """Transfer native SOL."""
        async with AsyncClient(rpc_url) as client:
            recipient_pubkey = Pubkey.from_string(recipient)
            lamports = int(amount * 1_000_000_000)

            instructions = []

            transfer_ix = system_transfer(
                {
                    "from_pubkey": signer.pubkey,
                    "to_pubkey": recipient_pubkey,
                    "lamports": lamports
                }
            )
            instructions.append(transfer_ix)

            recent_blockhash_resp = await client.get_latest_blockhash()
            recent_blockhash = recent_blockhash_resp.value.blockhash

            message = MessageV0.try_compile(
                payer=signer.pubkey,
                instructions=instructions,
                address_lookup_table_accounts=[],
                recent_blockhash=recent_blockhash,
            )

            transaction = signer.sign_versioned_transaction(message)

            response = await client.send_transaction(transaction)
            signature = str(response.value)

            return ToolResult(output={
                "success": True,
                "signature": signature,
                "amount": display_amount,
                "recipient": recipient,
                "signer_type": signer.signer_type,
            })

    async def _transfer_spl_token(
        self,
        rpc_url: str,
        signer: SolanaSigner,
        recipient: str,
        amount: float,
        token_address: str,
        display_amount
    ) -> ToolResult:
        async with AsyncClient(rpc_url) as client:
            recipient_pubkey = Pubkey.from_string(recipient)
            mint_pubkey = Pubkey.from_string(token_address)

            mint_info = await client.get_account_info(mint_pubkey, encoding="jsonParsed")
            decimals = 9
            if mint_info.value:
                parsed = getattr(mint_info.value.data, "parsed", None)
                if isinstance(parsed, dict):
                    info = parsed.get("info")
                    if isinstance(info, dict) and "decimals" in info:
                        decimals = info["decimals"]

            token_amount = int(amount * (10 ** decimals))

            sender_ata = Pubkey.from_string(
                get_associated_token_address(token_address, signer.get_address())
            )
            recipient_ata = Pubkey.from_string(
                get_associated_token_address(token_address, str(recipient_pubkey))
            )

            instructions = []

            recipient_ata_info = await client.get_account_info(recipient_ata)
            if not recipient_ata_info.value:
                create_ata_ix = create_associated_token_account(
                    payer=signer.pubkey,
                    owner=recipient_pubkey,
                    mint=mint_pubkey,
                )
                instructions.append(create_ata_ix)

            transfer_ix = transfer(
                {
                    "program_id": Pubkey.from_string(TOKEN_PROGRAM_ID),
                    "source": sender_ata,
                    "dest": recipient_ata,
                    "owner": signer.pubkey,
                    "amount": token_amount,
                }
            )
            instructions.append(transfer_ix)

            recent_blockhash_resp = await client.get_latest_blockhash()
            recent_blockhash = recent_blockhash_resp.value.blockhash

            message = MessageV0.try_compile(
                payer=signer.pubkey,
                instructions=instructions,
                address_lookup_table_accounts=[],
                recent_blockhash=recent_blockhash,
            )

            transaction = signer.sign_versioned_transaction(message)

            response = await client.send_transaction(transaction)
            signature = str(response.value)

            return ToolResult(output={
                "success": True,
                "signature": signature,
                "amount": display_amount,
                "recipient": recipient,
                "signer_type": signer.signer_type,
            })
