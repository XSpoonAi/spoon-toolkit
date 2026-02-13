"""Neo balance query tool.

Query NEP-17 token balances (NEO, GAS, or custom tokens) directly via RPC
using neo-mamba's ChainFacade and NEP17Contract wrappers.
"""

import logging
from typing import Optional

from pydantic import Field

from spoon_ai.tools.base import BaseTool, ToolResult
from .transfer_tools import _get_rpc_url

logger = logging.getLogger(__name__)


class NeoGetBalanceTool(BaseTool):
    """Get NEP-17 token balance for a Neo N3 address.

    Queries balance directly via RPC node using neo-mamba. Supports NEO, GAS,
    and any NEP-17 compliant token. Returns human-readable amounts with decimals.
    """

    name: str = "neo_get_balance"
    description: str = (
        "Get NEP-17 token balance for a Neo N3 address. "
        "Supports NEO, GAS, or any NEP-17 token by contract hash. "
        "Useful when you need to check how much NEO, GAS, or other tokens an address holds. "
        "Returns balance in human-readable format with proper decimal handling."
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
            "address": {
                "type": "string",
                "description": "Neo address to query (Base58 format, e.g. NXV2zshzasps7nqz2kcrv69zWhksVSG87D)",
            },
            "token": {
                "type": "string",
                "description": "Token to query: 'NEO', 'GAS', or a contract hash (0x-prefixed). Defaults to GAS.",
                "default": "GAS",
            },
        },
        "required": ["address"],
    }

    network: str = Field(default="testnet")
    address: Optional[str] = Field(default=None)
    token: str = Field(default="GAS")

    async def execute(
        self,
        address: Optional[str] = None,
        token: Optional[str] = None,
        network: Optional[str] = None,
    ) -> ToolResult:
        try:
            network = network or self.network or "testnet"
            address = address or self.address
            token = token or self.token or "GAS"

            if not address:
                return ToolResult(error="Missing address parameter")

            from neo3.api.wrappers import (
                ChainFacade,
                NEP17Contract,
                NeoToken,
                GasToken,
            )
            from neo3.core import types

            rpc_url = _get_rpc_url(network)
            facade = ChainFacade(rpc_host=rpc_url)

            # Resolve token contract
            token_upper = token.upper()
            if token_upper == "NEO":
                token_contract = NeoToken()
                token_symbol = "NEO"
            elif token_upper == "GAS":
                token_contract = GasToken()
                token_symbol = "GAS"
            else:
                contract_hash = token
                if not contract_hash.startswith("0x"):
                    contract_hash = f"0x{contract_hash}"
                token_contract = NEP17Contract(types.UInt160.from_string(contract_hash))
                # Query symbol
                try:
                    symbol_receipt = await facade.test_invoke(token_contract.symbol())
                    token_symbol = symbol_receipt.result
                except Exception:
                    token_symbol = contract_hash

            # Query balance (friendly = human-readable with decimals)
            balance_receipt = await facade.test_invoke(
                token_contract.balance_of_friendly(address)
            )
            balance = balance_receipt.result

            # Also get raw balance for precision
            raw_receipt = await facade.test_invoke(
                token_contract.balance_of(address)
            )
            raw_balance = raw_receipt.result

            return ToolResult(output={
                "address": address,
                "token": token_symbol,
                "balance": balance,
                "raw_balance": raw_balance,
                "network": network,
            })

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoGetBalanceTool error: {err_msg}")
            return ToolResult(error=f"Balance query failed: {err_msg}")
