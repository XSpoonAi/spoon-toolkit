"""Utilities for loading Solana keypairs and public keys."""

import base64
import logging
import os
from typing import Any, Iterable, Optional

import base58
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from .types import KeypairResult

logger = logging.getLogger(__name__)

PRIVATE_KEY_KEYS = ("SOLANA_PRIVATE_KEY", "WALLET_PRIVATE_KEY")
PUBLIC_KEY_KEYS = ("SOLANA_PUBLIC_KEY", "WALLET_PUBLIC_KEY")


def _is_encrypted(value: str) -> bool:
    """Check if a value is an encrypted secret (ENC: prefix)."""
    return value.startswith("ENC:")


def _get_from_vault(key: str) -> Optional[str]:
    """Try to retrieve a decrypted secret from SecretVault."""
    try:
        from spoon_ai.wallet.vault import get_vault
        vault = get_vault()
        if vault.exists(key):
            raw = vault.get_raw(key)
            if raw:
                return raw.decode("utf-8")
    except ImportError:
        pass
    except Exception as e:
        logger.debug("Failed to get %s from vault: %s", key, e)
    return None


def _auto_decrypt_to_vault(env_key: str) -> bool:
    """
    Auto-decrypt an encrypted env var and store in vault.

    Returns True if decryption succeeded, False otherwise.
    """
    enc_value = os.getenv(env_key)
    if not enc_value or not _is_encrypted(enc_value):
        return False

    try:
        from spoon_ai.wallet.vault import get_vault
        from spoon_ai.wallet.security import decrypt_and_store

        vault = get_vault()

        # Already decrypted?
        if vault.exists(env_key):
            return True

        # Get master password
        password = os.getenv("SPOON_MASTER_PWD")
        if not password:
            import sys
            import getpass
            try:
                if sys.stdin.isatty():
                    password = getpass.getpass(
                        f"Enter password to decrypt {env_key}: "
                    )
            except Exception:
                pass

        if not password:
            logger.warning(
                f"Encrypted {env_key} found but no password available. "
                f"Set SPOON_MASTER_PWD or run interactively."
            )
            return False

        # Decrypt and store
        decrypt_and_store(enc_value, password, env_key, vault=vault)
        logger.info(f"Decrypted {env_key} and stored in vault.")
        return True

    except ImportError as e:
        logger.warning(f"Cannot decrypt {env_key}: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to decrypt {env_key}: {e}")
        return False


def _runtime_get(runtime: Any, key: str) -> Optional[str]:
    """Attempt to retrieve a configuration value from an agent runtime."""
    if runtime is None:
        return None

    for attr in ("get_setting", "getSetting", "get"):
        getter = getattr(runtime, attr, None)
        if callable(getter):
            try:
                value = getter(key)
            except TypeError:
                # Getter signature mismatch, try the next option
                continue
            if value is not None:
                return value

    settings = getattr(runtime, "settings", None)
    if isinstance(settings, dict):
        return settings.get(key)

    return None


def _first_non_empty(values: Iterable[Optional[str]]) -> Optional[str]:
    """Return the first non-empty string from an iterable."""
    for value in values:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped
        elif value:
            return value  # Already a truthy value (e.g., bytes)
    return None


def _read_setting(runtime: Any, keys: Iterable[str]) -> Optional[str]:
    resolved = (
        _runtime_get(runtime, key) if runtime else os.getenv(key)
        for key in keys
    )
    return _first_non_empty(resolved)


def _decode_private_key(private_key: str) -> Keypair:
    """Decode a private key string into a Keypair object.

    The decoding attempts base58 first and then base64, mirroring the
    behaviour implemented in the TypeScript utilities.
    """
    if not isinstance(private_key, str):
        raise TypeError("Private key must be provided as a string")

    last_error: Optional[Exception] = None

    try:
        secret = base58.b58decode(private_key)
        if len(secret) != 64:
            raise ValueError("Invalid private key length (expected 64 bytes)")
        return Keypair.from_bytes(secret)
    except Exception as exc:  # pylint: disable=broad-except
        last_error = exc
        logger.debug("Failed to decode private key as base58: %s", exc)

    try:
        secret = base64.b64decode(private_key)
        if len(secret) != 64:
            raise ValueError("Invalid private key length (expected 64 bytes)")
        return Keypair.from_bytes(secret)
    except Exception as exc:  # pylint: disable=broad-except
        last_error = exc
        logger.debug("Failed to decode private key as base64: %s", exc)

    raise ValueError("Unable to decode private key") from last_error


def get_private_key(runtime: Any = None) -> Optional[str]:
    """
    Return the configured Solana private key string, if available.

    Priority order:
    1. Plain private key from env (not encrypted)
    2. Decrypted key from SecretVault (auto-decrypt ENC:v2 if needed)
    """
    for key in PRIVATE_KEY_KEYS:
        # Check runtime first
        if runtime:
            value = _runtime_get(runtime, key)
            if value and not _is_encrypted(value):
                return value

        # Check plain env
        env_value = os.getenv(key)
        if env_value and not _is_encrypted(env_value):
            return env_value

        # Check vault (already decrypted)
        vault_value = _get_from_vault(key)
        if vault_value:
            return vault_value

        # Try auto-decrypt if encrypted in env
        if env_value and _is_encrypted(env_value):
            if _auto_decrypt_to_vault(key):
                vault_value = _get_from_vault(key)
                if vault_value:
                    return vault_value

    return None


def get_public_key(runtime: Any = None) -> Optional[str]:
    """Return the configured Solana public key string, if available."""
    return _read_setting(runtime, PUBLIC_KEY_KEYS)


def get_wallet_keypair(
    runtime: Any = None,
    *,
    require_private_key: bool = True,
    private_key: Optional[str] = None,
    public_key: Optional[str] = None,
) -> KeypairResult:
    """Get a Solana wallet keypair or public key from runtime or environment settings.

    Args:
        runtime: Optional runtime object providing configuration.
        require_private_key: Whether a private key is required.
        private_key: Optional private key override string.
        public_key: Optional public key override string.

    Returns:
        KeypairResult containing either a ``keypair`` when ``require_private_key``
        is True, or a ``public_key`` otherwise.
    """
    if require_private_key:
        private_key_str = _first_non_empty(
            [private_key, get_private_key(runtime)]
        )
        if not private_key_str:
            raise ValueError("Private key not found in runtime settings or environment variables")

        keypair = _decode_private_key(private_key_str)
        return KeypairResult(keypair=keypair, public_key=keypair.pubkey())

    public_key_str = _first_non_empty(
        [public_key, get_public_key(runtime)]
    )

    if public_key_str:
        try:
            pubkey = Pubkey.from_string(public_key_str)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("Failed to parse public key '%s': %s", public_key_str, exc)
            raise ValueError("Invalid public key format") from exc
        return KeypairResult(public_key=pubkey)

    # If only a private key is supplied, derive the public key
    if private_key:
        keypair = _decode_private_key(private_key)
        return KeypairResult(public_key=keypair.pubkey())

    raise ValueError("Public key not found in runtime settings or environment variables")


def get_wallet_key(
    require_private_key: bool = True,
    private_key: Optional[str] = None,
    runtime: Any = None,
) -> KeypairResult:
    """Backward-compatible wrapper matching previous utility signature."""
    return get_wallet_keypair(
        runtime=runtime,
        require_private_key=require_private_key,
        private_key=private_key,
    )


__all__ = [
    "get_private_key",
    "get_public_key",
    "get_wallet_keypair",
    "get_wallet_key",
]
