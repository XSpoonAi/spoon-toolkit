"""Solana toolkit exports for SpoonAI."""

# Transfer tools
from .transfer import SolanaTransferTool

# Swap tools
from .swap import SolanaSwapTool

# Wallet management tools
from .wallet import (
    SolanaWalletInfoTool,
)

# Blockchain service tools and helpers
from .service import (
    SolanaService,
    create_request_headers,
    detect_private_keys_from_string,
    detect_pubkeys_from_string,
    format_token_amount,
    get_api_key,
    get_rpc_url,
    get_wallet_cache_scheduler,
    is_native_sol,
    lamports_to_sol,
    parse_token_amount,
    parse_transaction_error,
    sol_to_lamports,
    truncate_address,
    validate_private_key,
    validate_solana_address,
    verify_solana_signature,
)

# Keypair utilities
from .keypairUtils import get_wallet_keypair, get_wallet_key, get_private_key, get_public_key

# Signer interface (local & Turnkey)
from .signers import (
    SignerError,
    SolanaSigner,
    LocalSigner,
    TurnkeySigner,
    SignerManager,
    get_default_signer,
    set_default_signer,
    has_signer_credentials,
)

# Plugin integration
from .index import solana_plugin, PluginManifest, ProviderDefinition, wallet_provider, init_plugin

# Environment helpers
from .environment import load_solana_config, SolanaConfig

# Shared constants
from .constants import NATIVE_SOL_ADDRESS, TOKEN_ADDRESSES, DEFAULT_SLIPPAGE_BPS, JUPITER_PRIORITY_LEVELS

# Typed models
from .types import (
    WalletPortfolio,
    Item,
    Prices,
    TransferContent,
    SwapContent,
    KeypairResult,
    TokenMetadata,
)

__all__ = [
    # Transfer tools
    "SolanaTransferTool",
    # Swap tools
    "SolanaSwapTool",
    # Wallet tools
    "SolanaWalletInfoTool",
    # Service class
    "SolanaService",
    # Service tools & helpers
    "create_request_headers",
    "detect_private_keys_from_string",
    "detect_pubkeys_from_string",
    "format_token_amount",
    "get_api_key",
    "get_rpc_url",
    "get_wallet_cache_scheduler",
    "is_native_sol",
    "lamports_to_sol",
    "parse_token_amount",
    "parse_transaction_error",
    "sol_to_lamports",
    "truncate_address",
    "validate_private_key",
    "validate_solana_address",
    "verify_solana_signature",
    # Key utilities
    "get_wallet_keypair",
    "get_wallet_key",
    "get_private_key",
    "get_public_key",
    # Signer interface
    "SignerError",
    "SolanaSigner",
    "LocalSigner",
    "TurnkeySigner",
    "SignerManager",
    "get_default_signer",
    "set_default_signer",
    "has_signer_credentials",
    # Plugin integration
    "solana_plugin",
    "PluginManifest",
    "ProviderDefinition",
    "wallet_provider",
    "init_plugin",
    # Environment helpers
    "load_solana_config",
    "SolanaConfig",
    # Constants
    "NATIVE_SOL_ADDRESS",
    "TOKEN_ADDRESSES",
    "DEFAULT_SLIPPAGE_BPS",
    "JUPITER_PRIORITY_LEVELS",
    # Typed models
    "WalletPortfolio",
    "Item",
    "Prices",
    "TransferContent",
    "SwapContent",
    "KeypairResult",
    "TokenMetadata",
]
