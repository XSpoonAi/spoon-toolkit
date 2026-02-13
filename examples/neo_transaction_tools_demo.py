"""
Neo Transaction Tools Demo - Demonstrates 12 on-chain operation tools

This example demonstrates the Neo N3 transaction/operation tools built on neo-mamba:

  Read-only tools (no private key required):
    1. NeoGetBalanceTool        - Query NEP-17 token balances
    2. NeoTestInvokeTool        - Test invoke contracts (free, read-only)
    3. NeoEstimateGasTool       - Estimate GAS cost before sending
    4. NeoMultiSigCreateTool    - Create multi-signature accounts
    5. NeoContractStorageTool   - Query contract storage entries

  Transaction tools (require NEO_PRIVATE_KEY):
    6. NeoTransferTool          - Transfer NEO/GAS/NEP-17 tokens
    7. NeoNep11TransferTool     - Transfer NEP-11 NFTs
    8. NeoInvokeContractTool    - Invoke contract methods (state-changing)
    9. NeoBatchInvokeTool       - Batch multiple contract calls in one tx
   10. NeoClaimGasTool          - Claim unclaimed GAS
   11. NeoVoteTool              - Vote for consensus candidates
   12. NeoDeployContractTool    - Deploy smart contracts

Usage:
    # Run read-only demos (no private key needed):
    python examples/neo_transaction_tools_demo.py

    # Run all demos including transactions (requires private key):
    NEO_PRIVATE_KEY=<your_wif_or_hex> python examples/neo_transaction_tools_demo.py --live

Uses testnet for all demonstrations.
"""

import asyncio
import os
import sys
import json

# ---------------------------------------------------------------------------
# Test data (Neo N3 Testnet)
# ---------------------------------------------------------------------------
NETWORK = "testnet"

# Well-known testnet addresses (no private key needed for read queries)
TEST_ADDRESS = "NUTtedVrz5RgKAdCvtKiq3sRkb9pizcewe"
TEST_CONTRACT_NEO = "0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5"
TEST_CONTRACT_GAS = "0xd2a4cff31913016155e38e474a2c06d08be276cf"

# Optional: set these env vars to enable the corresponding demo
# NEO_TEST_NFT_CONTRACT   - NEP-11 contract hash for NFT transfer demo
# NEO_TEST_NFT_TOKEN_ID   - token ID you own on that contract
# NEO_TEST_NFT_TO_ADDRESS - recipient address (defaults to TEST_ADDRESS)
# NEO_TEST_CANDIDATE_PUBKEY - candidate public key for vote demo
# NEO_TEST_NEF_PATH       - path to .nef file for deploy demo
# NEO_TEST_MANIFEST_PATH  - path to .manifest.json for deploy demo


# ===========================================================================
# Helper
# ===========================================================================
def section(title: str):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def result_json(result) -> str:
    """Pretty-print a ToolResult."""
    if result.error:
        return f"  ERROR: {result.error}"
    data = result.output
    if isinstance(data, dict):
        return json.dumps(data, indent=2, default=str)
    return str(data)


# ===========================================================================
# 1. NeoGetBalanceTool
# ===========================================================================
async def demo_get_balance():
    section("1. NeoGetBalanceTool - Query token balances")

    from spoon_toolkits.crypto.neo import NeoGetBalanceTool

    tool = NeoGetBalanceTool()

    # Query GAS balance
    print(f"\n--- Query GAS balance for {TEST_ADDRESS} ---")
    res = await tool.execute(address=TEST_ADDRESS, token="GAS", network=NETWORK)
    print(result_json(res))

    # Query NEO balance
    print(f"\n--- Query NEO balance for {TEST_ADDRESS} ---")
    res = await tool.execute(address=TEST_ADDRESS, token="NEO", network=NETWORK)
    print(result_json(res))


# ===========================================================================
# 2. NeoTestInvokeTool
# ===========================================================================
async def demo_test_invoke():
    section("2. NeoTestInvokeTool - Read-only contract invocation (free)")

    from spoon_toolkits.crypto.neo import NeoTestInvokeTool

    tool = NeoTestInvokeTool()

    # Query NEO token symbol
    print(f"\n--- Test invoke: NeoToken.symbol() ---")
    res = await tool.execute(
        contract_hash=TEST_CONTRACT_NEO,
        method="symbol",
        network=NETWORK,
    )
    print(result_json(res))

    # Query GAS token decimals
    print(f"\n--- Test invoke: GasToken.decimals() ---")
    res = await tool.execute(
        contract_hash=TEST_CONTRACT_GAS,
        method="decimals",
        network=NETWORK,
    )
    print(result_json(res))

    # Query NEO totalSupply
    print(f"\n--- Test invoke: NeoToken.totalSupply() ---")
    res = await tool.execute(
        contract_hash=TEST_CONTRACT_NEO,
        method="totalSupply",
        network=NETWORK,
    )
    print(result_json(res))


# ===========================================================================
# 3. NeoEstimateGasTool
# ===========================================================================
async def demo_estimate_gas():
    section("3. NeoEstimateGasTool - Estimate GAS cost")

    from spoon_toolkits.crypto.neo import NeoEstimateGasTool

    tool = NeoEstimateGasTool()

    # Estimate gas for querying symbol (read-only, cheap)
    print(f"\n--- Estimate GAS: NeoToken.symbol() ---")
    res = await tool.execute(
        contract_hash=TEST_CONTRACT_NEO,
        method="symbol",
        network=NETWORK,
    )
    print(result_json(res))

    # Estimate gas for a transfer (more expensive)
    print(f"\n--- Estimate GAS: GasToken.balanceOf({TEST_ADDRESS}) ---")
    res = await tool.execute(
        contract_hash=TEST_CONTRACT_GAS,
        method="balanceOf",
        args=[{"type": "Hash160", "value": TEST_ADDRESS}],
        signer_address=TEST_ADDRESS,
        network=NETWORK,
    )
    print(result_json(res))


# ===========================================================================
# 4. NeoMultiSigCreateTool
# ===========================================================================
async def demo_multisig_create():
    section("4. NeoMultiSigCreateTool - Create multi-signature account")

    from spoon_toolkits.crypto.neo import NeoMultiSigCreateTool

    tool = NeoMultiSigCreateTool()

    # Create a 2-of-3 multisig using example public keys
    # (These are well-known testnet committee member keys)
    print("\n--- Create 2-of-3 multi-sig account ---")
    res = await tool.execute(
        public_keys=[
            "02208aea0068c429a03316e37be0e3e8e21e6cda5442df4c5914a19b3a9b6de375",
            "0306d3e7f18e6dd477d34ce3cfeca172a877f3c907cc6c2b66c295d1fcc76ff8f7",
            "02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765",
        ],
        threshold=2,
    )
    print(result_json(res))


# ===========================================================================
# 5. NeoContractStorageTool
# ===========================================================================
async def demo_contract_storage():
    section("5. NeoContractStorageTool - Query contract storage")

    from spoon_toolkits.crypto.neo import NeoContractStorageTool

    tool = NeoContractStorageTool()

    # Query NEO token storage (first 5 entries)
    print(f"\n--- Query NeoToken contract storage (first 5 entries) ---")
    res = await tool.execute(
        contract_hash=TEST_CONTRACT_NEO,
        prefix="",
        limit=5,
        network=NETWORK,
    )
    print(result_json(res))


# ===========================================================================
# 6. NeoTransferTool
# ===========================================================================
async def demo_transfer():
    section("6. NeoTransferTool - Transfer NEP-17 tokens")

    from spoon_toolkits.crypto.neo import NeoTransferTool

    tool = NeoTransferTool()

    # Transfer a small amount of GAS on testnet
    print(f"\n--- Transfer 0.001 GAS to {TEST_ADDRESS} ---")
    res = await tool.execute(
        to_address=TEST_ADDRESS,
        amount="0.001",
        token="GAS",
        network=NETWORK,
    )
    print(result_json(res))


# ===========================================================================
# 7. NeoNep11TransferTool
# ===========================================================================
async def demo_nep11_transfer():
    section("7. NeoNep11TransferTool - Transfer NEP-11 NFT")

    from spoon_toolkits.crypto.neo import NeoNep11TransferTool

    tool = NeoNep11TransferTool()

    nft_contract = os.getenv("NEO_TEST_NFT_CONTRACT")
    nft_token_id = os.getenv("NEO_TEST_NFT_TOKEN_ID")
    nft_to = os.getenv("NEO_TEST_NFT_TO_ADDRESS", TEST_ADDRESS)

    if nft_contract and nft_token_id:
        print(f"\n--- Transfer NFT {nft_token_id[:20]}... to {nft_to} ---")
        res = await tool.execute(
            contract_hash=nft_contract,
            to_address=nft_to,
            token_id=nft_token_id,
            network=NETWORK,
        )
        print(result_json(res))
    else:
        missing = []
        if not nft_contract:
            missing.append("NEO_TEST_NFT_CONTRACT")
        if not nft_token_id:
            missing.append("NEO_TEST_NFT_TOKEN_ID")
        print(f"\n--- Skipped: set {', '.join(missing)} env var(s) to enable ---")
        print("    Usage example:")
        print('    await tool.execute(')
        print('        contract_hash="0x<nep11_contract>",')
        print('        to_address="NXV2zsh...",')
        print('        token_id="<hex_or_utf8_token_id>",')
        print(f'        network="{NETWORK}",')
        print("    )")


# ===========================================================================
# 8. NeoInvokeContractTool
# ===========================================================================
async def demo_invoke_contract():
    section("8. NeoInvokeContractTool - State-changing contract invocation")

    from spoon_toolkits.crypto.neo import NeoInvokeContractTool

    tool = NeoInvokeContractTool()

    # Example: invoke GAS token transfer (small amount to self)
    # This is a real on-chain tx that costs GAS
    print(f"\n--- Invoke: GasToken.transfer(self -> self, 1 satoshi) ---")
    print("    This sends a minimal self-transfer to demonstrate invocation.")

    # We need the sender address from the private key
    from spoon_toolkits.crypto.neo.transfer_tools import (
        _resolve_private_key,
        _create_neo3_account,
    )

    key = _resolve_private_key()
    account = _create_neo3_account(key)
    sender = str(account.address)

    res = await tool.execute(
        contract_hash=TEST_CONTRACT_GAS,
        method="transfer",
        args=[
            {"type": "Hash160", "value": sender},
            {"type": "Hash160", "value": sender},
            {"type": "Integer", "value": 1},
            None,
        ],
        network=NETWORK,
    )
    print(result_json(res))


# ===========================================================================
# 9. NeoBatchInvokeTool
# ===========================================================================
async def demo_batch_invoke():
    section("9. NeoBatchInvokeTool - Batch contract calls in one tx")

    from spoon_toolkits.crypto.neo import NeoBatchInvokeTool
    from spoon_toolkits.crypto.neo.transfer_tools import (
        _resolve_private_key,
        _create_neo3_account,
    )

    tool = NeoBatchInvokeTool()

    key = _resolve_private_key()
    account = _create_neo3_account(key)
    sender = str(account.address)

    # Batch: query NEO symbol + GAS symbol in one tx
    # (Read-only methods batched in a state-changing tx for demo)
    print("\n--- Batch invoke: NeoToken.symbol() + GasToken.symbol() ---")
    res = await tool.execute(
        calls=[
            {"contract_hash": TEST_CONTRACT_NEO, "method": "symbol"},
            {"contract_hash": TEST_CONTRACT_GAS, "method": "symbol"},
        ],
        network=NETWORK,
    )
    print(result_json(res))


# ===========================================================================
# 10. NeoClaimGasTool
# ===========================================================================
async def demo_claim_gas():
    section("10. NeoClaimGasTool - Claim unclaimed GAS")

    from spoon_toolkits.crypto.neo import NeoClaimGasTool

    tool = NeoClaimGasTool()

    print("\n--- Check and claim unclaimed GAS ---")
    res = await tool.execute(network=NETWORK)
    print(result_json(res))


# ===========================================================================
# 11. NeoVoteTool
# ===========================================================================
async def demo_vote():
    section("11. NeoVoteTool - Vote for consensus candidate")

    from spoon_toolkits.crypto.neo import NeoVoteTool

    tool = NeoVoteTool()

    candidate_pubkey = os.getenv("NEO_TEST_CANDIDATE_PUBKEY")

    if candidate_pubkey:
        print(f"\n--- Vote for candidate {candidate_pubkey[:20]}... ---")
        res = await tool.execute(
            candidate_pubkey=candidate_pubkey,
            network=NETWORK,
        )
        print(result_json(res))
    else:
        print("\n--- Skipped: set NEO_TEST_CANDIDATE_PUBKEY env var to enable ---")
        print("    Usage example:")
        print('    await tool.execute(')
        print('        candidate_pubkey="02208aea0068c429a03316e37be0e3e8e21e6cda...",')
        print(f'        network="{NETWORK}",')
        print("    )")


# ===========================================================================
# 12. NeoDeployContractTool
# ===========================================================================
async def demo_deploy_contract():
    section("12. NeoDeployContractTool - Deploy smart contract")

    from spoon_toolkits.crypto.neo import NeoDeployContractTool

    tool = NeoDeployContractTool()

    nef_path = os.getenv("NEO_TEST_NEF_PATH")
    manifest_path = os.getenv("NEO_TEST_MANIFEST_PATH")

    if nef_path and manifest_path:
        nef_exists = os.path.isfile(nef_path)
        manifest_exists = os.path.isfile(manifest_path)
        if nef_exists and manifest_exists:
            print(f"\n--- Deploy contract: {os.path.basename(nef_path)} ---")
            res = await tool.execute(
                nef_path=nef_path,
                manifest_path=manifest_path,
                network=NETWORK,
            )
            print(result_json(res))
        else:
            if not nef_exists:
                print(f"\n--- Skipped: NEF file not found: {nef_path} ---")
            if not manifest_exists:
                print(f"--- Skipped: Manifest file not found: {manifest_path} ---")
    else:
        missing = []
        if not nef_path:
            missing.append("NEO_TEST_NEF_PATH")
        if not manifest_path:
            missing.append("NEO_TEST_MANIFEST_PATH")
        print(f"\n--- Skipped: set {', '.join(missing)} env var(s) to enable ---")
        print("    Usage example:")
        print('    await tool.execute(')
        print('        nef_path="./my_contract.nef",')
        print('        manifest_path="./my_contract.manifest.json",')
        print(f'        network="{NETWORK}",')
        print("    )")


# ===========================================================================
# Main
# ===========================================================================
async def main():
    live_mode = "--live" in sys.argv

    print("=" * 70)
    print("  Neo N3 Transaction Tools Demo")
    print("=" * 70)
    print(f"  Network:    {NETWORK}")
    print(f"  Mode:       {'LIVE (transactions enabled)' if live_mode else 'READ-ONLY (no private key needed)'}")
    if live_mode:
        pk = os.getenv("NEO_PRIVATE_KEY")
        print(f"  Private key: {'set' if pk else 'NOT SET (transactions will fail)'}")
    print("=" * 70)

    # -----------------------------------------------------------------------
    # Part 1: Read-only tools (always run, no private key needed)
    # -----------------------------------------------------------------------
    print("\n\n>>> PART 1: Read-Only Tools (no private key required) <<<\n")

    await demo_get_balance()
    await demo_test_invoke()
    await demo_estimate_gas()
    await demo_multisig_create()
    await demo_contract_storage()

    # -----------------------------------------------------------------------
    # Part 2: Transaction tools (only with --live flag)
    # -----------------------------------------------------------------------
    if not live_mode:
        section("PART 2: Transaction Tools (skipped)")
        print("\n  Re-run with --live flag and NEO_PRIVATE_KEY set to enable:")
        print("    NEO_PRIVATE_KEY=<your_wif> python examples/neo_transaction_tools_demo.py --live")
        print("\n  Tools that would be demonstrated:")
        print("    6.  NeoTransferTool        - Transfer GAS/NEO/NEP-17")
        print("    7.  NeoNep11TransferTool   - Transfer NFTs")
        print("    8.  NeoInvokeContractTool  - State-changing contract call")
        print("    9.  NeoBatchInvokeTool     - Batch contract calls")
        print("    10. NeoClaimGasTool        - Claim unclaimed GAS")
        print("    11. NeoVoteTool            - Vote for candidates")
        print("    12. NeoDeployContractTool  - Deploy contracts")
        return

    print("\n\n>>> PART 2: Transaction Tools (LIVE - costs testnet GAS) <<<\n")

    await demo_transfer()
    await demo_nep11_transfer()
    await demo_invoke_contract()
    await demo_batch_invoke()
    await demo_claim_gas()
    await demo_vote()
    await demo_deploy_contract()

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    section("Demo Complete")
    print("\n  12 Neo transaction/operation tools demonstrated:")
    print("  Read-only:    NeoGetBalance, NeoTestInvoke, NeoEstimateGas,")
    print("                NeoMultiSigCreate, NeoContractStorage")
    print("  Transactions: NeoTransfer, NeoNep11Transfer, NeoInvokeContract,")
    print("                NeoBatchInvoke, NeoClaimGas, NeoVote, NeoDeployContract")
    print()


if __name__ == "__main__":
    asyncio.run(main())
