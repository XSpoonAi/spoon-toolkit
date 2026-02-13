"""Shared helpers for Neo on-chain tools.

Provides common utilities used across multiple Neo tool modules:
- RPC URL resolution
- Private key resolution (env / vault / explicit)
- neo3 account creation
- Transaction state checking (VMState)
- Error message sanitization
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# RPC configuration
# ---------------------------------------------------------------------------
DEFAULT_MAINNET_RPC = "https://mainmagnet.ngd.network:443"
DEFAULT_TESTNET_RPC = "https://testmagnet.ngd.network:443"


def get_rpc_url(network: str) -> str:
    """Resolve RPC URL from network name and environment variables."""
    if network == "mainnet":
        return os.getenv("NEO_MAINNET_RPC", DEFAULT_MAINNET_RPC)
    return os.getenv("NEO_TESTNET_RPC", DEFAULT_TESTNET_RPC)


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------
def resolve_private_key(private_key: Optional[str] = None) -> str:
    """Resolve private key from parameter, env var, or vault.

    Priority: explicit param -> plain env -> vault-decrypted env.

    Returns:
        Private key string (WIF or hex).

    Raises:
        ValueError: if no private key can be resolved.
    """
    from .signers import ENV_PRIVATE_KEY, _is_encrypted, _get_private_key_from_vault

    if private_key:
        return private_key.strip()

    env_key = os.getenv(ENV_PRIVATE_KEY)
    if env_key and not _is_encrypted(env_key):
        return env_key.strip()

    vault_key = _get_private_key_from_vault()
    if vault_key:
        return vault_key.strip()

    raise ValueError(
        f"No private key available. Provide private_key parameter or set {ENV_PRIVATE_KEY} env var."
    )


def create_neo3_account(private_key: str):
    """Create a neo3 Account from a WIF or hex private key.

    Returns:
        neo3.wallet.account.Account instance.
    """
    from neo3.wallet.account import Account

    # Try WIF first
    try:
        return Account.from_wif(private_key)
    except Exception:
        pass

    # Try hex private key
    key_hex = private_key
    if key_hex.startswith("0x"):
        key_hex = key_hex[2:]
    key_bytes = bytes.fromhex(key_hex)
    return Account.from_private_key(key_bytes)


# ---------------------------------------------------------------------------
# Transaction state helpers
# ---------------------------------------------------------------------------
def is_halt(receipt) -> bool:
    """Check whether a transaction receipt indicates successful execution.

    Handles both ``VMState`` enum (from ``invoke``) and plain string
    (from ``test_invoke``).
    """
    try:
        from neo3.vm import VMState
        if receipt.state == VMState.HALT:
            return True
    except ImportError:
        pass
    # Fallback: string comparison for test_invoke or unknown formats
    return "HALT" in str(receipt.state)


def state_label(receipt) -> str:
    """Return a human-readable state string from a receipt."""
    try:
        from neo3.vm import VMState
        if receipt.state == VMState.HALT:
            return "HALT"
    except ImportError:
        pass
    raw = str(receipt.state)
    if "HALT" in raw:
        return "HALT"
    return raw


# ---------------------------------------------------------------------------
# Error formatting
# ---------------------------------------------------------------------------
def sanitize_error(exception_detail) -> str:
    """Sanitize an internal exception detail for external consumption.

    Strips overly verbose stack traces, keeping only the first line.
    """
    if not exception_detail:
        return ""
    msg = str(exception_detail)
    first_line = msg.split("\n")[0].strip()
    if len(first_line) > 200:
        first_line = first_line[:200] + "..."
    return first_line
