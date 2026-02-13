"""Neo smart contract deployment tool.

Deploy smart contracts to the Neo N3 blockchain using neo-mamba's ChainFacade.
Supports loading NEF (Neo Executable Format) and manifest files from disk or raw bytes.
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
from ._helpers import is_halt, state_label, sanitize_error

logger = logging.getLogger(__name__)


class NeoDeployContractTool(BaseTool):
    """Deploy a smart contract to the Neo N3 blockchain.

    Loads compiled NEF and manifest files, then deploys them via a transaction.
    Returns the deployed contract hash and transaction details.
    """

    name: str = "neo_deploy_contract"
    description: str = (
        "Deploy a smart contract to the Neo N3 blockchain. "
        "Requires compiled NEF (Neo Executable Format) and manifest JSON files. "
        "Useful when you need to deploy a new smart contract on-chain. "
        "Returns the new contract hash, transaction hash, and deployment details."
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
            "nef_path": {
                "type": "string",
                "description": "Path to the compiled .nef file",
            },
            "manifest_path": {
                "type": "string",
                "description": "Path to the contract .manifest.json file",
            },
            "data": {
                "type": "object",
                "description": "Optional data passed to the contract's _deploy method",
            },
            "private_key": {
                "type": "string",
                "description": "Deployer private key (WIF or hex). If omitted, uses NEO_PRIVATE_KEY env var.",
            },
        },
        "required": ["nef_path", "manifest_path"],
    }

    network: str = Field(default="testnet")
    nef_path: Optional[str] = Field(default=None)
    manifest_path: Optional[str] = Field(default=None)
    data: Optional[dict] = Field(default=None)
    private_key: Optional[str] = Field(default=None)

    async def execute(
        self,
        nef_path: Optional[str] = None,
        manifest_path: Optional[str] = None,
        data: Optional[dict] = None,
        network: Optional[str] = None,
        private_key: Optional[str] = None,
    ) -> ToolResult:
        try:
            network = network or self.network or "testnet"
            nef_path = nef_path or self.nef_path
            manifest_path = manifest_path or self.manifest_path
            data = data if data is not None else self.data
            private_key = private_key or self.private_key

            if not nef_path:
                return ToolResult(error="Missing nef_path parameter")
            if not manifest_path:
                return ToolResult(error="Missing manifest_path parameter")

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
            from neo3.network.payloads.verification import Signer, WitnessScope
            from neo3.contracts.nef import NEF
            from neo3.contracts.manifest import ContractManifest

            # Load NEF file
            try:
                contract_nef = NEF.from_file(nef_path)
            except Exception as e:
                return ToolResult(error=f"Failed to load NEF file '{nef_path}': {e}")

            # Load manifest
            try:
                contract_manifest = ContractManifest.from_file(manifest_path)
            except Exception as e:
                return ToolResult(error=f"Failed to load manifest file '{manifest_path}': {e}")

            # Setup facade with GLOBAL scope (deployment needs broader permissions)
            rpc_url = _get_rpc_url(network)
            facade = ChainFacade(rpc_host=rpc_url)
            facade.add_signer(
                sign_with_account(account),
                Signer(account.script_hash, WitnessScope.GLOBAL),
            )

            # Build deploy call
            deploy_call = GenericContract.deploy(
                nef=contract_nef,
                manifest=contract_manifest,
                data=data,
            )

            source_address = str(account.address)

            # Execute deployment
            receipt = await facade.invoke(deploy_call)
            success = is_halt(receipt)
            s_label = state_label(receipt)

            result = {
                "tx_hash": str(receipt.tx_hash),
                "success": success,
                "state": s_label,
                "deployer": source_address,
                "gas_consumed": receipt.gas_consumed,
                "included_in_block": receipt.included_in_block,
                "network": network,
            }

            # Extract deployed contract hash from result
            if success and receipt.result:
                result["contract_hash"] = str(receipt.result)

            if receipt.exception:
                result["exception"] = sanitize_error(receipt.exception)

            if not success:
                return ToolResult(error=f"Deployment failed: {sanitize_error(receipt.exception) or s_label}", output=result)

            return ToolResult(output=result)

        except Exception as e:
            err_msg = str(e) or repr(e)
            logger.error(f"NeoDeployContractTool error: {err_msg}")
            return ToolResult(error=f"Contract deployment failed: {err_msg}")
