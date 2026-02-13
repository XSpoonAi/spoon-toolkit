"""Neo smart contract storage query tool.

Query smart contract storage on the Neo N3 blockchain using RPC node.
Supports prefix-based filtering and pagination for large storage sets.
"""

import logging
from typing import Optional

from pydantic import Field

from spoon_ai.tools.base import BaseTool, ToolResult
from .transfer_tools import _get_rpc_url

logger = logging.getLogger(__name__)


class NeoContractStorageTool(BaseTool):
    """Query smart contract storage on the Neo N3 blockchain.

    Read storage entries from a deployed smart contract. Supports prefix-based
    filtering to narrow results and handles pagination for large storage sets.
    Useful for inspecting contract state, token balances, or any on-chain data.
    """

    name: str = "neo_contract_storage"
    description: str = (
        "Query smart contract storage on the Neo N3 blockchain. "
        "Useful when you need to read raw storage entries from a deployed contract, "
        "inspect contract state, or look up specific storage keys. "
        "Supports prefix-based filtering. Returns key-value pairs in hex format."
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
                "description": "Contract script hash (0x-prefixed)",
            },
            "prefix": {
                "type": "string",
                "description": "Storage key prefix to filter results (hex-encoded). If omitted, returns all storage entries.",
                "default": "",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of entries to return. Default 100.",
                "default": 100,
            },
        },
        "required": ["contract_hash"],
    }

    network: str = Field(default="testnet")
    contract_hash: Optional[str] = Field(default=None)
    prefix: str = Field(default="")
    limit: int = Field(default=100)

    async def execute(
        self,
        contract_hash: Optional[str] = None,
        prefix: Optional[str] = None,
        limit: Optional[int] = None,
        network: Optional[str] = None,
    ) -> ToolResult:
        try:
            network = network or self.network or "testnet"
            contract_hash = contract_hash or self.contract_hash
            prefix = prefix if prefix is not None else self.prefix
            limit = limit or self.limit

            if not contract_hash:
                return ToolResult(error="Missing contract_hash parameter")

            from neo3.api import noderpc
            from neo3.core import types

            if not contract_hash.startswith("0x"):
                contract_hash = f"0x{contract_hash}"

            rpc_url = _get_rpc_url(network)

            # Convert prefix from hex string to bytes
            prefix_bytes = bytes.fromhex(prefix) if prefix else b""

            entries = []
            async with noderpc.NeoRpcClient(rpc_url) as client:
                count = 0
                async for key, value in client.find_states(
                    types.UInt160.from_string(contract_hash),
                    prefix_bytes,
                ):
                    entries.append({
                        "key": key.hex() if isinstance(key, bytes) else str(key),
                        "value": value.hex() if isinstance(value, bytes) else str(value),
                    })
                    count += 1
                    if count >= limit:
                        break

            return ToolResult(output={
                "contract": contract_hash,
                "prefix": prefix,
                "entries": entries,
                "count": len(entries),
                "truncated": len(entries) >= limit,
                "network": network,
            })

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoContractStorageTool error: {err_msg}")
            return ToolResult(error=f"Storage query failed: {err_msg}")
