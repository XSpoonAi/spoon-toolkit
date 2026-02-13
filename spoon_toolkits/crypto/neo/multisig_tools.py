"""Neo multi-signature account tools.

Create and manage multi-signature accounts on the Neo N3 blockchain.
Multi-sig accounts require M-of-N signatures to authorize transactions.
"""

import logging
from typing import Optional, List

from pydantic import Field

from spoon_ai.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class NeoMultiSigCreateTool(BaseTool):
    """Create a multi-signature account on the Neo N3 blockchain.

    Generates an M-of-N multi-sig account from a list of public keys.
    The resulting account requires at least M signatures from the N participants
    to authorize any transaction.
    """

    name: str = "neo_create_multisig"
    description: str = (
        "Create a multi-signature account on the Neo N3 blockchain. "
        "Useful when you need to set up a shared account that requires multiple "
        "signatures (M-of-N) to authorize transactions. "
        "Returns the multi-sig address, script hash, and verification script."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "public_keys": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of public keys (hex-encoded, e.g. ['02abc...', '03def...']). These are the N participants.",
            },
            "threshold": {
                "type": "integer",
                "description": "Minimum number of signatures required (M). Must be between 1 and the number of public keys.",
            },
        },
        "required": ["public_keys", "threshold"],
    }

    public_keys: Optional[List[str]] = Field(default=None)
    threshold: Optional[int] = Field(default=None)

    async def execute(
        self,
        public_keys: Optional[List[str]] = None,
        threshold: Optional[int] = None,
    ) -> ToolResult:
        try:
            public_keys = public_keys or self.public_keys
            threshold = threshold or self.threshold

            if not public_keys:
                return ToolResult(error="Missing public_keys parameter")
            if not threshold:
                return ToolResult(error="Missing threshold parameter")
            if threshold < 1:
                return ToolResult(error="Threshold must be at least 1")
            if threshold > len(public_keys):
                return ToolResult(error=f"Threshold ({threshold}) cannot exceed number of public keys ({len(public_keys)})")

            from neo3.core import cryptography, utils as coreutils
            from neo3.contracts import utils as contractutils
            from neo3.wallet import utils as walletutils

            # Parse public keys
            ec_points = []
            for pk_hex in public_keys:
                pk = pk_hex
                if pk.startswith("0x"):
                    pk = pk[2:]
                try:
                    ec_point = cryptography.ECPoint.deserialize_from_bytes(
                        bytes.fromhex(pk)
                    )
                    ec_points.append(ec_point)
                except Exception as e:
                    return ToolResult(error=f"Invalid public key '{pk_hex}': {e}")

            # Create multi-sig redeem script
            multisig_script = contractutils.create_multisig_redeemscript(
                threshold, ec_points
            )

            # Derive script hash and address
            script_hash = coreutils.to_script_hash(multisig_script)
            address = walletutils.script_hash_to_address(script_hash)

            return ToolResult(output={
                "address": str(address),
                "script_hash": f"0x{script_hash}",
                "threshold": threshold,
                "participants": len(public_keys),
                "public_keys": public_keys,
                "verification_script": multisig_script.hex(),
            })

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoMultiSigCreateTool error: {err_msg}")
            return ToolResult(error=f"Multi-sig creation failed: {err_msg}")
