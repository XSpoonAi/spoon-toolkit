"""Neo smart contract invocation tools.

Provides tools for invoking smart contract methods on the Neo N3 blockchain,
both state-changing (costs GAS) and read-only (free) invocations.
Uses neo-mamba's ChainFacade for transaction lifecycle management.
"""

import os
import json
import logging
from typing import Optional, List, Any

from pydantic import Field

from spoon_ai.tools.base import BaseTool, ToolResult
from .transfer_tools import (
    _get_rpc_url,
    _resolve_private_key,
    _create_neo3_account,
)
from ._helpers import is_halt, state_label, sanitize_error

logger = logging.getLogger(__name__)


def _parse_contract_args(args: Optional[List[Any]]) -> Optional[list]:
    """Parse contract arguments into neo3-compatible format.

    Supports basic types: int, str, bool, bytes (hex-encoded), and UInt160 (0x-prefixed hash).
    Each arg can be a raw value or a dict with {"type": ..., "value": ...} for explicit typing.

    Supported explicit types:
        - "Integer" / "int": integer value
        - "String" / "str": string value
        - "Boolean" / "bool": boolean value
        - "ByteArray" / "bytes": hex-encoded byte array
        - "Hash160" / "address": Neo address or 0x-prefixed script hash → UInt160
        - "Hash256": 0x-prefixed 256-bit hash → UInt256
        - "Array": list of nested args

    Returns:
        List of parsed arguments, or None if args is None/empty.
    """
    if not args:
        return None

    from neo3.core import types
    from neo3.wallet import utils as walletutils

    parsed = []
    for arg in args:
        if arg is None:
            parsed.append(None)
            continue
        if isinstance(arg, dict) and "type" in arg and "value" in arg:
            arg_type = arg["type"].lower()
            value = arg["value"]

            if arg_type in ("integer", "int"):
                parsed.append(int(value))
            elif arg_type in ("string", "str"):
                parsed.append(str(value))
            elif arg_type in ("boolean", "bool"):
                parsed.append(bool(value))
            elif arg_type in ("bytearray", "bytes"):
                if isinstance(value, str):
                    parsed.append(bytes.fromhex(value.replace("0x", "")))
                else:
                    parsed.append(bytes(value))
            elif arg_type in ("hash160", "address"):
                value_str = str(value)
                if value_str.startswith("0x"):
                    parsed.append(types.UInt160.from_string(value_str))
                else:
                    # Assume Neo address
                    script_hash = walletutils.address_to_script_hash(value_str)
                    parsed.append(script_hash)
            elif arg_type == "hash256":
                parsed.append(types.UInt256.from_string(str(value)))
            elif arg_type == "array":
                parsed.append(_parse_contract_args(value))
            else:
                # Unknown type, pass as-is
                parsed.append(value)
        elif isinstance(arg, bool):
            parsed.append(arg)
        elif isinstance(arg, int):
            parsed.append(arg)
        elif isinstance(arg, str):
            # Heuristic: if it looks like a script hash, convert to UInt160
            if arg.startswith("0x") and len(arg) == 42:
                parsed.append(types.UInt160.from_string(arg))
            else:
                parsed.append(arg)
        else:
            parsed.append(arg)

    return parsed


class NeoInvokeContractTool(BaseTool):
    """Invoke a smart contract method on the Neo N3 blockchain (state-changing, costs GAS).

    Builds, signs, and broadcasts a contract invocation transaction.
    """

    name: str = "neo_invoke_contract"
    description: str = (
        "Invoke a smart contract method on the Neo N3 blockchain. "
        "This is a state-changing operation that costs GAS. "
        "Useful when you need to call a contract method that modifies on-chain state. "
        "Returns transaction hash, execution state, gas consumed, and notifications."
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
                "description": "Contract script hash (0x-prefixed, e.g. 0xd2a4cff31913016155e38e474a2c06d08be276cf)",
            },
            "method": {
                "type": "string",
                "description": "Contract method name to invoke",
            },
            "args": {
                "type": "array",
                "description": (
                    "Arguments for the method. Each arg can be a raw value (int, string, bool) "
                    "or a dict with {\"type\": \"...\", \"value\": \"...\"} for explicit typing. "
                    "Supported types: Integer, String, Boolean, ByteArray, Hash160, Hash256, Array."
                ),
                "items": {},
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
        "required": ["contract_hash", "method"],
    }

    network: str = Field(default="testnet")
    contract_hash: Optional[str] = Field(default=None)
    method: Optional[str] = Field(default=None)
    args: Optional[List[Any]] = Field(default=None)
    private_key: Optional[str] = Field(default=None)
    wait_for_receipt: bool = Field(default=True)

    async def execute(
        self,
        contract_hash: Optional[str] = None,
        method: Optional[str] = None,
        args: Optional[List[Any]] = None,
        network: Optional[str] = None,
        private_key: Optional[str] = None,
        wait_for_receipt: Optional[bool] = None,
    ) -> ToolResult:
        try:
            # Resolve parameters
            network = network or self.network or "testnet"
            contract_hash = contract_hash or self.contract_hash
            method = method or self.method
            args = args if args is not None else self.args
            private_key = private_key or self.private_key
            wait_for_receipt = wait_for_receipt if wait_for_receipt is not None else self.wait_for_receipt

            if not contract_hash:
                return ToolResult(error="Missing contract_hash parameter")
            if not method:
                return ToolResult(error="Missing method parameter")

            # Resolve private key and create account
            try:
                key = _resolve_private_key(private_key)
            except ValueError as e:
                return ToolResult(error=str(e))

            try:
                account = _create_neo3_account(key)
            except Exception as e:
                return ToolResult(error=f"Failed to create account from private key: {e}")

            # Lazy imports
            from neo3.api.wrappers import ChainFacade, GenericContract
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

            # Build contract call
            if not contract_hash.startswith("0x"):
                contract_hash = f"0x{contract_hash}"
            contract = GenericContract(types.UInt160.from_string(contract_hash))

            parsed_args = _parse_contract_args(args)
            call = contract.call_function(method, parsed_args)

            # Execute
            source_address = str(account.address)

            if wait_for_receipt:
                receipt = await facade.invoke(call)
                success = is_halt(receipt)
                s_label = state_label(receipt)

                # Format notifications
                notifications = []
                for n in receipt.notifications:
                    notifications.append({
                        "contract": str(n.contract),
                        "event_name": n.event_name,
                        "state": str(n.state),
                    })

                result = {
                    "tx_hash": str(receipt.tx_hash),
                    "success": success,
                    "state": s_label,
                    "gas_consumed": receipt.gas_consumed,
                    "included_in_block": receipt.included_in_block,
                    "confirmations": receipt.confirmations,
                    "from": source_address,
                    "contract": contract_hash,
                    "method": method,
                    "notifications": notifications,
                    "network": network,
                }

                if receipt.exception:
                    result["exception"] = sanitize_error(receipt.exception)

                if not success:
                    return ToolResult(error=f"Contract invocation failed: {sanitize_error(receipt.exception) or s_label}", output=result)

                return ToolResult(output=result)
            else:
                tx_hash = await facade.invoke_fast(call)
                return ToolResult(output={
                    "tx_hash": str(tx_hash),
                    "status": "submitted",
                    "from": source_address,
                    "contract": contract_hash,
                    "method": method,
                    "network": network,
                })

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoInvokeContractTool error: {err_msg}")
            return ToolResult(error=f"Contract invocation failed: {err_msg}")


class NeoTestInvokeTool(BaseTool):
    """Test invoke a smart contract method on Neo N3 (read-only, no GAS cost).

    Executes the contract method without persisting state changes.
    Useful for querying contract state or estimating gas before a real invocation.
    """

    name: str = "neo_test_invoke"
    description: str = (
        "Test invoke a smart contract method on the Neo N3 blockchain (read-only, no GAS cost). "
        "Useful when you need to query contract state, estimate gas cost, or preview "
        "the result of a contract method before actually sending a transaction. "
        "Returns execution result, gas estimate, and stack output."
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
            "method": {
                "type": "string",
                "description": "Contract method name to invoke",
            },
            "args": {
                "type": "array",
                "description": (
                    "Arguments for the method. Each arg can be a raw value (int, string, bool) "
                    "or a dict with {\"type\": \"...\", \"value\": \"...\"} for explicit typing."
                ),
                "items": {},
            },
            "signer_address": {
                "type": "string",
                "description": "Optional signer address for authorization context (Neo address or 0x-prefixed script hash). Some methods require a signer to return correct results.",
            },
        },
        "required": ["contract_hash", "method"],
    }

    network: str = Field(default="testnet")
    contract_hash: Optional[str] = Field(default=None)
    method: Optional[str] = Field(default=None)
    args: Optional[List[Any]] = Field(default=None)
    signer_address: Optional[str] = Field(default=None)

    async def execute(
        self,
        contract_hash: Optional[str] = None,
        method: Optional[str] = None,
        args: Optional[List[Any]] = None,
        network: Optional[str] = None,
        signer_address: Optional[str] = None,
    ) -> ToolResult:
        try:
            # Resolve parameters
            network = network or self.network or "testnet"
            contract_hash = contract_hash or self.contract_hash
            method = method or self.method
            args = args if args is not None else self.args
            signer_address = signer_address or self.signer_address

            if not contract_hash:
                return ToolResult(error="Missing contract_hash parameter")
            if not method:
                return ToolResult(error="Missing method parameter")

            # Lazy imports
            from neo3.api.wrappers import ChainFacade, GenericContract
            from neo3.network.payloads.verification import Signer
            from neo3.core import types
            from neo3.wallet import utils as walletutils

            # Setup facade
            rpc_url = _get_rpc_url(network)
            facade = ChainFacade(rpc_host=rpc_url)

            # Add test signer if provided
            if signer_address:
                if signer_address.startswith("0x"):
                    signer_hash = types.UInt160.from_string(signer_address)
                else:
                    signer_hash = walletutils.address_to_script_hash(signer_address)
                facade.add_test_signer(Signer(signer_hash))

            # Build contract call
            if not contract_hash.startswith("0x"):
                contract_hash = f"0x{contract_hash}"
            contract = GenericContract(types.UInt160.from_string(contract_hash))

            parsed_args = _parse_contract_args(args)
            call = contract.call_function(method, parsed_args)

            # Test invoke
            receipt = await facade.test_invoke(call)
            success = is_halt(receipt)
            s_label = state_label(receipt)

            # Format stack output
            stack_output = []
            if hasattr(receipt.result, 'stack'):
                for item in receipt.result.stack:
                    stack_output.append({
                        "type": str(item.type) if hasattr(item, 'type') else type(item).__name__,
                        "value": str(item.value) if hasattr(item, 'value') else str(item),
                    })
            else:
                stack_output.append({"value": str(receipt.result)})

            # Format notifications
            notifications = []
            for n in receipt.notifications:
                notifications.append({
                    "contract": str(n.contract),
                    "event_name": n.event_name,
                    "state": str(n.state),
                })

            result = {
                "success": success,
                "state": s_label,
                "gas_consumed": receipt.gas_consumed,
                "stack": stack_output,
                "notifications": notifications,
                "contract": contract_hash,
                "method": method,
                "network": network,
            }

            if receipt.exception:
                result["exception"] = sanitize_error(receipt.exception)

            if not success:
                return ToolResult(error=f"Test invocation faulted: {sanitize_error(receipt.exception) or s_label}", output=result)

            return ToolResult(output=result)

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoTestInvokeTool error: {err_msg}")
            return ToolResult(error=f"Test invocation failed: {err_msg}")


class NeoBatchInvokeTool(BaseTool):
    """Invoke multiple smart contract methods in a single transaction on Neo N3.

    Batches multiple contract calls into one transaction, reducing overall GAS cost
    and ensuring atomicity (all calls succeed or all fail).
    """

    name: str = "neo_batch_invoke"
    description: str = (
        "Invoke multiple smart contract methods in a single transaction on Neo N3. "
        "Useful when you need to execute several contract calls atomically and save GAS. "
        "All calls are concatenated into one transaction; if any fails, all revert. "
        "Returns transaction hash, execution state, and per-call results."
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
            "calls": {
                "type": "array",
                "description": (
                    "List of contract calls. Each call is an object with: "
                    "'contract_hash' (0x-prefixed), 'method' (string), and optional 'args' (array)."
                ),
                "items": {
                    "type": "object",
                    "properties": {
                        "contract_hash": {"type": "string"},
                        "method": {"type": "string"},
                        "args": {"type": "array", "items": {}},
                    },
                    "required": ["contract_hash", "method"],
                },
            },
            "private_key": {
                "type": "string",
                "description": "Sender private key (WIF or hex). If omitted, uses NEO_PRIVATE_KEY env var.",
            },
        },
        "required": ["calls"],
    }

    network: str = Field(default="testnet")
    calls: Optional[List[dict]] = Field(default=None)
    private_key: Optional[str] = Field(default=None)

    async def execute(
        self,
        calls: Optional[List[dict]] = None,
        network: Optional[str] = None,
        private_key: Optional[str] = None,
    ) -> ToolResult:
        try:
            network = network or self.network or "testnet"
            calls = calls or self.calls
            private_key = private_key or self.private_key

            if not calls or len(calls) == 0:
                return ToolResult(error="Missing or empty calls parameter")

            try:
                key = _resolve_private_key(private_key)
            except ValueError as e:
                return ToolResult(error=str(e))

            try:
                account = _create_neo3_account(key)
            except Exception as e:
                return ToolResult(error=f"Failed to create account from private key: {e}")

            from neo3.api.wrappers import ChainFacade, GenericContract
            from neo3.api.helpers.signing import sign_with_account
            from neo3.network.payloads.verification import Signer
            from neo3.core import types

            rpc_url = _get_rpc_url(network)
            facade = ChainFacade(rpc_host=rpc_url)
            facade.add_signer(
                sign_with_account(account),
                Signer(account.script_hash),
            )

            # Build all contract calls
            contract_calls = []
            for i, call_def in enumerate(calls):
                contract_hash = call_def.get("contract_hash", "")
                method = call_def.get("method", "")
                args = call_def.get("args")

                if not contract_hash or not method:
                    return ToolResult(error=f"Call #{i}: missing contract_hash or method")

                if not contract_hash.startswith("0x"):
                    contract_hash = f"0x{contract_hash}"
                contract = GenericContract(types.UInt160.from_string(contract_hash))
                parsed_args = _parse_contract_args(args)
                contract_calls.append(contract.call_function(method, parsed_args))

            source_address = str(account.address)

            # Execute batch
            receipt = await facade.invoke_multi(contract_calls)
            success = is_halt(receipt)
            s_label = state_label(receipt)

            # Format per-call results
            call_results = []
            if isinstance(receipt.result, (list, tuple)):
                for i, r in enumerate(receipt.result):
                    call_results.append({
                        "index": i,
                        "result": str(r),
                    })

            notifications = []
            for n in receipt.notifications:
                notifications.append({
                    "contract": str(n.contract),
                    "event_name": n.event_name,
                    "state": str(n.state),
                })

            result = {
                "tx_hash": str(receipt.tx_hash),
                "success": success,
                "state": s_label,
                "gas_consumed": receipt.gas_consumed,
                "included_in_block": receipt.included_in_block,
                "from": source_address,
                "calls_count": len(calls),
                "call_results": call_results,
                "notifications": notifications,
                "network": network,
            }

            if receipt.exception:
                result["exception"] = sanitize_error(receipt.exception)

            if not success:
                return ToolResult(error=f"Batch invocation failed: {sanitize_error(receipt.exception) or s_label}", output=result)

            return ToolResult(output=result)

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoBatchInvokeTool error: {err_msg}")
            return ToolResult(error=f"Batch invocation failed: {err_msg}")


class NeoEstimateGasTool(BaseTool):
    """Estimate GAS cost for a smart contract invocation on Neo N3.

    Simulates the contract call without broadcasting and returns the estimated
    system fee (GAS consumed by the VM). Useful for previewing costs.
    """

    name: str = "neo_estimate_gas"
    description: str = (
        "Estimate GAS cost for a smart contract invocation on Neo N3. "
        "Useful when you need to know how much GAS a contract call will cost "
        "before actually sending the transaction. Does not broadcast anything. "
        "Returns estimated GAS in both raw (integer) and human-readable formats."
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
            "method": {
                "type": "string",
                "description": "Contract method name",
            },
            "args": {
                "type": "array",
                "description": "Arguments for the method",
                "items": {},
            },
            "signer_address": {
                "type": "string",
                "description": "Optional signer address for fee estimation context (Neo address or 0x-prefixed script hash).",
            },
        },
        "required": ["contract_hash", "method"],
    }

    network: str = Field(default="testnet")
    contract_hash: Optional[str] = Field(default=None)
    method: Optional[str] = Field(default=None)
    args: Optional[List[Any]] = Field(default=None)
    signer_address: Optional[str] = Field(default=None)

    async def execute(
        self,
        contract_hash: Optional[str] = None,
        method: Optional[str] = None,
        args: Optional[List[Any]] = None,
        network: Optional[str] = None,
        signer_address: Optional[str] = None,
    ) -> ToolResult:
        try:
            network = network or self.network or "testnet"
            contract_hash = contract_hash or self.contract_hash
            method = method or self.method
            args = args if args is not None else self.args
            signer_address = signer_address or self.signer_address

            if not contract_hash:
                return ToolResult(error="Missing contract_hash parameter")
            if not method:
                return ToolResult(error="Missing method parameter")

            from neo3.api.wrappers import ChainFacade, GenericContract
            from neo3.network.payloads.verification import Signer
            from neo3.core import types
            from neo3.wallet import utils as walletutils

            rpc_url = _get_rpc_url(network)
            facade = ChainFacade(rpc_host=rpc_url)

            # Build signers list for estimation
            signers = None
            if signer_address:
                if signer_address.startswith("0x"):
                    signer_hash = types.UInt160.from_string(signer_address)
                else:
                    signer_hash = walletutils.address_to_script_hash(signer_address)
                signers = [Signer(signer_hash)]

            # Build contract call
            if not contract_hash.startswith("0x"):
                contract_hash = f"0x{contract_hash}"
            contract = GenericContract(types.UInt160.from_string(contract_hash))

            parsed_args = _parse_contract_args(args)
            call = contract.call_function(method, parsed_args)

            # Estimate gas
            gas_raw = await facade.estimate_gas(call, signers=signers)
            gas_human = gas_raw / 10**8  # GAS has 8 decimals

            return ToolResult(output={
                "contract": contract_hash,
                "method": method,
                "estimated_gas": gas_human,
                "estimated_gas_raw": gas_raw,
                "network": network,
            })

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoEstimateGasTool error: {err_msg}")
            return ToolResult(error=f"Gas estimation failed: {err_msg}")
