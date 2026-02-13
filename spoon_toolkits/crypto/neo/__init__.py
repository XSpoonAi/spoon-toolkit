"""Neo blockchain tools module"""

# Apply neo-mamba compatibility fixes before importing any tools
from . import _compat as _neo_compat
_neo_compat.apply()

# Address tools
from .address_tools import (
    GetAddressCountTool,
    GetAddressInfoTool,
    ValidateAddressTool,
    GetActiveAddressesTool,
    GetTotalSentAndReceivedTool,
    GetTransferByAddressTool,
)

# Asset tools
from .asset_tools import (
    GetAssetCountTool,
    GetAssetInfoByHashTool,
    GetAssetInfoByNameTool,
    GetAssetInfosTool,
    GetAssetInfoByAssetAndAddressTool,
)

# Block tools
from .block_tools import (
    GetBlockCountTool,
    GetBlockByHashTool,
    GetBlockByHeightTool,
    GetBestBlockHashTool,
    GetRecentBlocksInfoTool,
    GetBlockRewardByHashTool,
)

# Contract tools
from .contract_tools import (
    GetContractCountTool,
    GetContractByHashTool,
    GetContractListByNameTool,
    GetVerifiedContractByContractHashTool,
    GetVerifiedContractTool,
)

# Transaction tools
from .transaction_tools import (
    GetTransactionCountTool,
    GetTransactionCountByAddressTool,
    GetRawTransactionByBlockHashTool,
    GetRawTransactionByBlockHeightTool,
    GetRawTransactionByTransactionHashTool,
    GetRawTransactionByAddressTool,
    GetTransferByBlockHashTool,
    GetTransferByBlockHeightTool,
    GetTransferEventByTransactionHashTool,
)

# Voting tools
from .voting_tools import (
    GetCandidateCountTool,
    GetCandidateByAddressTool,
    GetCandidateByVoterAddressTool,
    GetScVoteCallByCandidateAddressTool,
    GetScVoteCallByTransactionHashTool,
    GetScVoteCallByVoterAddressTool,
    GetVotersByCandidateAddressTool,
    GetVotesByCandidateAddressTool,
    GetTotalVotesTool,
)

# NEP tools
from .nep_tools import (
    GetNep11BalanceTool,
    GetNep11ByAddressAndHashTool,
    GetNep11TransferByAddressTool,
    GetNep11TransferByBlockHeightTool,
    GetNep11TransferByTransactionHashTool,
    GetNep11TransferCountByAddressTool,
    GetNep17TransferByAddressTool,
    GetNep17TransferByBlockHeightTool,
    GetNep17TransferByContractHashTool,
    GetNep17TransferByTransactionHashTool,
    GetNep17TransferCountByAddressTool,
)

# Smart Contract Call tools
from .sc_call_tools import (
    GetScCallByContractHashTool,
    GetScCallByContractHashAddressTool,
    GetScCallByTransactionHashTool,
)

# Application Log and State tools
from .log_state_tools import (
    GetApplicationLogTool,
    GetApplicationStateTool,
)

# Governance tools
from .governance_tools import (
    GetCommitteeInfoTool,
)

# Transfer tools (on-chain transaction sending)
from .transfer_tools import (
    NeoTransferTool,
    NeoNep11TransferTool,
)

# Contract invocation tools (on-chain + test invoke + batch + estimate)
from .invoke_tools import (
    NeoInvokeContractTool,
    NeoTestInvokeTool,
    NeoBatchInvokeTool,
    NeoEstimateGasTool,
)

# Balance tools
from .balance_tools import (
    NeoGetBalanceTool,
)

# Governance action tools (claim GAS, vote)
from .governance_action_tools import (
    NeoClaimGasTool,
    NeoVoteTool,
)

# Contract deployment tools
from .deploy_tools import (
    NeoDeployContractTool,
)

# Multi-signature tools
from .multisig_tools import (
    NeoMultiSigCreateTool,
)

# Contract storage tools
from .storage_tools import (
    NeoContractStorageTool,
)

# Provider
from .neo_provider import NeoProvider
from .base import get_provider

__all__ = [
    # Address tools (6)
    "GetAddressCountTool",
    "GetAddressInfoTool",
    "ValidateAddressTool",
    "GetActiveAddressesTool",
    "GetTotalSentAndReceivedTool",
    "GetTransferByAddressTool",
    
    # Asset tools (5)
    "GetAssetCountTool",
    "GetAssetInfoByHashTool",
    "GetAssetInfoByNameTool",
    "GetAssetInfosTool",
    "GetAssetInfoByAssetAndAddressTool",
    
    # Block tools (6)
    "GetBlockCountTool",
    "GetBlockByHashTool",
    "GetBlockByHeightTool",
    "GetBestBlockHashTool",
    "GetRecentBlocksInfoTool",
    "GetBlockRewardByHashTool",
    
    # Contract tools (5)
    "GetContractCountTool",
    "GetContractByHashTool",
    "GetContractListByNameTool",
    "GetVerifiedContractByContractHashTool",
    "GetVerifiedContractTool",
    
    # Transaction tools (9)
    "GetTransactionCountTool",
    "GetTransactionCountByAddressTool",
    "GetRawTransactionByBlockHashTool",
    "GetRawTransactionByBlockHeightTool",
    "GetRawTransactionByTransactionHashTool",
    "GetRawTransactionByAddressTool",
    "GetTransferByBlockHashTool",
    "GetTransferByBlockHeightTool",
    "GetTransferEventByTransactionHashTool",
    
    # Voting tools (9)
    "GetCandidateCountTool",
    "GetCandidateByAddressTool",
    "GetCandidateByVoterAddressTool",
    "GetScVoteCallByCandidateAddressTool",
    "GetScVoteCallByTransactionHashTool",
    "GetScVoteCallByVoterAddressTool",
    "GetVotersByCandidateAddressTool",
    "GetVotesByCandidateAddressTool",
    "GetTotalVotesTool",
    
    # NEP tools (11)
    "GetNep11BalanceTool",
    "GetNep11ByAddressAndHashTool",
    "GetNep11TransferByAddressTool",
    "GetNep11TransferByBlockHeightTool",
    "GetNep11TransferByTransactionHashTool",
    "GetNep11TransferCountByAddressTool",
    "GetNep17TransferByAddressTool",
    "GetNep17TransferByBlockHeightTool",
    "GetNep17TransferByContractHashTool",
    "GetNep17TransferByTransactionHashTool",
    "GetNep17TransferCountByAddressTool",
    
    # Smart Contract Call tools (3)
    "GetScCallByContractHashTool",
    "GetScCallByContractHashAddressTool",
    "GetScCallByTransactionHashTool",
    
    # Application Log and State tools (2)
    "GetApplicationLogTool",
    "GetApplicationStateTool",

    # Governance tools (1)
    "GetCommitteeInfoTool",

    # Transfer tools (2)
    "NeoTransferTool",
    "NeoNep11TransferTool",

    # Contract invocation tools (4)
    "NeoInvokeContractTool",
    "NeoTestInvokeTool",
    "NeoBatchInvokeTool",
    "NeoEstimateGasTool",

    # Balance tools (1)
    "NeoGetBalanceTool",

    # Governance action tools (2)
    "NeoClaimGasTool",
    "NeoVoteTool",

    # Contract deployment tools (1)
    "NeoDeployContractTool",

    # Multi-signature tools (1)
    "NeoMultiSigCreateTool",

    # Contract storage tools (1)
    "NeoContractStorageTool",

    # Provider
    "NeoProvider",
    "get_provider",
] 