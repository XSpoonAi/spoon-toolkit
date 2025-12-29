"""
Unified signer interface for Neo tools supporting both local private key and Turnkey signing.

This module provides a clean abstraction for transaction signing, allowing Neo tools
to work with either local private keys (via neo3-boa) or Turnkey's secure API.

Note: Neo uses secp256r1 (P-256) curve, different from Ethereum's secp256k1.

Priority order for auto-detection:
1. Plain private key from environment variable (not encrypted)
2. Encrypted private key from SecretVault (ENC:v2 decrypted)
3. Turnkey remote signing
"""

import os
import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Union

logger = logging.getLogger(__name__)

# Environment variable keys
ENV_PRIVATE_KEY = "NEO_PRIVATE_KEY"
ENV_TURNKEY_SIGN_WITH = "NEO_TURNKEY_SIGN_WITH"
ENV_TURNKEY_ADDRESS = "NEO_TURNKEY_ADDRESS"


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


def _get_private_key_from_vault() -> Optional[str]:
    """
    Get decrypted private key from SecretVault.

    If an encrypted key exists in env but not in vault, auto-decrypt it first.
    """
    # Check if already in vault
    value = _get_from_vault(ENV_PRIVATE_KEY)
    if value:
        return value

    # Try auto-decrypt if encrypted in env
    env_value = os.getenv(ENV_PRIVATE_KEY)
    if env_value and _is_encrypted(env_value):
        if _auto_decrypt_to_vault(ENV_PRIVATE_KEY):
            return _get_from_vault(ENV_PRIVATE_KEY)

    return None


class SignerError(Exception):
    """Exception raised for signing-related errors."""
    pass


class NeoSigner(ABC):
    """Abstract base class for Neo transaction signers."""

    @abstractmethod
    async def sign_transaction(self, tx_bytes: bytes) -> bytes:
        """
        Sign a Neo transaction.

        Args:
            tx_bytes: Serialized transaction bytes to sign.

        Returns:
            Signature bytes.
        """
        pass

    @abstractmethod
    async def sign_message(self, message: bytes) -> bytes:
        """
        Sign an arbitrary message.

        Args:
            message: Message bytes to sign.

        Returns:
            Signature bytes.
        """
        pass

    @abstractmethod
    async def get_address(self) -> str:
        """
        Get the signer's Neo address.

        Returns:
            Neo address string (e.g., NiEtVMWVYgpXrWkRTMwRaMJtJ41gD3912N)
        """
        pass

    @abstractmethod
    async def get_script_hash(self) -> str:
        """
        Get the signer's script hash.

        Returns:
            Script hash as hex string (0x-prefixed)
        """
        pass

    @property
    @abstractmethod
    def signer_type(self) -> str:
        """Return the type of signer ('local' or 'turnkey')."""
        pass


class LocalSigner(NeoSigner):
    """Signer using local private key via neo3 library."""

    def __init__(self, private_key: str):
        """
        Initialize with private key.

        Args:
            private_key: Private key as WIF string or hex string.
        """
        if not private_key:
            raise ValueError("Private key is required")

        self._private_key = private_key.strip()
        self._account = None
        self._initialized = False

    def _ensure_initialized(self):
        """Lazy initialization of neo3 account."""
        if self._initialized:
            return

        try:
            from neo3.wallet import Account
            from neo3.core import types

            # Try WIF format first, then hex
            try:
                self._account = Account.from_wif(self._private_key)
            except Exception:
                # Try as hex private key
                if self._private_key.startswith("0x"):
                    key_hex = self._private_key[2:]
                else:
                    key_hex = self._private_key

                # Convert hex to bytes and create account
                key_bytes = bytes.fromhex(key_hex)
                self._account = Account.from_private_key(key_bytes)

            self._initialized = True

        except ImportError:
            raise SignerError(
                "neo3 library not installed. Install with: pip install neo3"
            )
        except Exception as e:
            raise SignerError(f"Failed to initialize Neo account: {e}")

    async def sign_transaction(self, tx_bytes: bytes) -> bytes:
        """Sign transaction using local private key."""
        self._ensure_initialized()
        try:
            from neo3.core.cryptography import sign

            # Neo uses SHA256 for transaction hashing
            import hashlib
            tx_hash = hashlib.sha256(tx_bytes).digest()

            signature = sign(tx_hash, self._account.private_key)
            return signature
        except Exception as e:
            raise SignerError(f"Local signing failed: {e}")

    async def sign_message(self, message: bytes) -> bytes:
        """Sign message using local private key."""
        self._ensure_initialized()
        try:
            from neo3.core.cryptography import sign

            # Hash the message first
            import hashlib
            msg_hash = hashlib.sha256(message).digest()

            signature = sign(msg_hash, self._account.private_key)
            return signature
        except Exception as e:
            raise SignerError(f"Message signing failed: {e}")

    async def get_address(self) -> str:
        """Get the account address."""
        self._ensure_initialized()
        return str(self._account.address)

    async def get_script_hash(self) -> str:
        """Get the account script hash."""
        self._ensure_initialized()
        return f"0x{self._account.script_hash}"

    @property
    def signer_type(self) -> str:
        return "local"


class TurnkeySigner(NeoSigner):
    """Signer using Turnkey API for secure key management.

    Note: Neo uses secp256r1 (P-256) curve. Ensure your Turnkey wallet
    is configured with CURVE_SECP256R1 and ADDRESS_FORMAT_NEO.
    """

    def __init__(self, sign_with: str, address: Optional[str] = None, turnkey_client=None):
        """
        Initialize with Turnkey signing identity.

        Args:
            sign_with: Turnkey signing identity (wallet account address / private key address / private key ID)
            address: Neo address for this signer (optional, for address resolution)
            turnkey_client: Optional Turnkey client instance, will create if not provided
        """
        self.sign_with = sign_with
        self._turnkey = turnkey_client
        self._cached_address: Optional[str] = address
        self._cached_script_hash: Optional[str] = None

    def _get_turnkey_client(self):
        """Lazy initialization of Turnkey client."""
        if self._turnkey is None:
            try:
                from spoon_ai.turnkey import Turnkey
                self._turnkey = Turnkey()
            except Exception as e:
                raise SignerError(f"Failed to initialize Turnkey client: {e}")
        return self._turnkey

    async def sign_transaction(self, tx_bytes: bytes) -> bytes:
        """Sign transaction using Turnkey API."""
        try:
            import hashlib

            # Neo uses SHA256 for transaction hashing
            tx_hash = hashlib.sha256(tx_bytes).digest()

            return await self._sign_raw_bytes(tx_hash)

        except Exception as e:
            raise SignerError(f"Turnkey signing failed: {e}")

    async def sign_message(self, message: bytes) -> bytes:
        """Sign message using Turnkey API."""
        try:
            import hashlib

            # Hash the message
            msg_hash = hashlib.sha256(message).digest()

            return await self._sign_raw_bytes(msg_hash)

        except Exception as e:
            raise SignerError(f"Turnkey message signing failed: {e}")

    async def _sign_raw_bytes(self, data: bytes) -> bytes:
        """
        Sign raw bytes using Turnkey sign_raw_payload API.

        Args:
            data: Bytes to sign (should be already hashed if needed).

        Returns:
            Signature bytes.
        """
        client = self._get_turnkey_client()

        # Convert to hex for Turnkey API
        payload_hex = data.hex()

        response = client._sign_raw_payload(
            sign_with=self.sign_with,
            payload=payload_hex,
            encoding="PAYLOAD_ENCODING_HEXADECIMAL",
            hash_function="HASH_FUNCTION_NO_OP",  # Data is already hashed
        )

        # Extract signature from response
        result = self._extract_result(response, "signRawPayloadResult")
        activity_id = self._extract_activity_id(response)

        if not result or not result.get("r"):
            # Poll for result if not immediately available
            import time
            start = time.time()
            timeout = 90.0

            while True:
                activity_resp = client.get_activity(activity_id)
                activity = activity_resp.get("activity", {})
                status = activity.get("status")

                if status == "ACTIVITY_STATUS_COMPLETED":
                    result = self._extract_result(activity, "signRawPayloadResult")
                    break
                if status in {"ACTIVITY_STATUS_FAILED", "ACTIVITY_STATUS_REJECTED"}:
                    raise SignerError(f"Turnkey signing failed with status {status}")
                if (time.time() - start) > timeout:
                    raise TimeoutError("Timed out waiting for Turnkey signing")

                time.sleep(1.0)

        return self._parse_signature(result)

    def _parse_signature(self, result: Dict[str, Any]) -> bytes:
        """Parse Turnkey signature result into bytes."""
        if not isinstance(result, dict):
            raise SignerError("Invalid Turnkey signature response")

        # Check for direct signature
        signature_hex = result.get("signature") or result.get("signatureHex")
        if signature_hex:
            return bytes.fromhex(signature_hex.replace("0x", ""))

        # Reconstruct from r and s
        r_hex = result.get("r", "")
        s_hex = result.get("s", "")

        if not r_hex or not s_hex:
            raise SignerError("Turnkey signature missing r or s components")

        r_hex = r_hex.replace("0x", "")
        s_hex = s_hex.replace("0x", "")

        # Pad to 32 bytes each for P-256 curve
        r_bytes = bytes.fromhex(r_hex.zfill(64))
        s_bytes = bytes.fromhex(s_hex.zfill(64))

        return r_bytes + s_bytes

    def _extract_activity_id(self, response: Dict[str, Any]) -> str:
        """Extract activity ID from Turnkey response."""
        activity = response.get("activity") if isinstance(response, dict) else None
        if not activity:
            raise SignerError("Turnkey response missing activity payload")
        activity_id = activity.get("id") or activity.get("activityId")
        if not activity_id:
            raise SignerError("Turnkey response missing activity id")
        return activity_id

    def _extract_result(self, payload: Dict[str, Any], result_key: str) -> Dict[str, Any]:
        """Extract result from Turnkey response payload."""
        if not isinstance(payload, dict):
            return {}
        result_root = (
            payload.get("result")
            or payload.get("activity", {}).get("result")
            or {}
        )
        if not isinstance(result_root, dict):
            return {}
        specific = result_root.get(result_key)
        if isinstance(specific, dict):
            return specific
        if not specific and result_root:
            return result_root
        return {}

    async def get_address(self) -> str:
        """Get the signing address."""
        if self._cached_address is None:
            raise SignerError(
                "Neo address not set. Provide address parameter or set NEO_TURNKEY_ADDRESS env var."
            )
        return self._cached_address

    async def get_script_hash(self) -> str:
        """Get the script hash from address."""
        if self._cached_script_hash:
            return self._cached_script_hash

        address = await self.get_address()

        try:
            from neo3.core import types
            from neo3.wallet import Account

            # Convert Neo address to script hash
            script_hash = Account.address_to_script_hash(address)
            self._cached_script_hash = f"0x{script_hash}"
            return self._cached_script_hash
        except ImportError:
            raise SignerError("neo3 library required for address conversion")
        except Exception as e:
            raise SignerError(f"Failed to convert address to script hash: {e}")

    @property
    def signer_type(self) -> str:
        return "turnkey"


class SignerManager:
    """Manager for creating and configuring Neo signers."""

    @staticmethod
    def create_signer(
        signer_type: str = "auto",
        private_key: Optional[str] = None,
        turnkey_sign_with: Optional[str] = None,
        turnkey_address: Optional[str] = None,
    ) -> NeoSigner:
        """
        Create a Neo signer based on configuration.

        Priority order for auto-detection:
        1. Plain private key from env (not encrypted)
        2. Encrypted private key from SecretVault
        3. Turnkey remote signing

        Args:
            signer_type: 'local', 'turnkey', or 'auto'
            private_key: Private key for local signing (WIF or hex)
            turnkey_sign_with: Turnkey signing identity
            turnkey_address: Turnkey signer's Neo address

        Returns:
            Configured NeoSigner instance
        """
        # Auto-detect signer type
        if signer_type == "auto":
            # Check explicit parameters first
            if private_key:
                signer_type = "local"
            elif turnkey_sign_with:
                signer_type = "turnkey"
            else:
                # Priority: plain env -> vault -> turnkey
                env_key = os.getenv(ENV_PRIVATE_KEY)

                # 1. Plain private key from env (not encrypted)
                if env_key and not _is_encrypted(env_key):
                    signer_type = "local"

                # 2. Encrypted private key from SecretVault
                elif _get_from_vault(ENV_PRIVATE_KEY):
                    signer_type = "local"

                # 3. Turnkey remote signing
                elif os.getenv(ENV_TURNKEY_SIGN_WITH):
                    signer_type = "turnkey"

                else:
                    raise ValueError(
                        "Cannot auto-detect signer type. Options:\n"
                        f"1. Set {ENV_PRIVATE_KEY} with plain private key\n"
                        f"2. Set {ENV_PRIVATE_KEY} with ENC:v2 encrypted key and decrypt to vault\n"
                        f"3. Set {ENV_TURNKEY_SIGN_WITH} for Turnkey signing"
                    )

        if signer_type == "local":
            # Try sources in priority order: param -> plain env -> vault
            key = private_key
            if not key:
                env_key = os.getenv(ENV_PRIVATE_KEY)
                if env_key and not _is_encrypted(env_key):
                    key = env_key
            if not key:
                key = _get_from_vault(ENV_PRIVATE_KEY)

            if not key:
                raise ValueError(
                    f"Private key required for local signing. "
                    f"Set {ENV_PRIVATE_KEY} or decrypt encrypted key to vault."
                )
            return LocalSigner(key)

        elif signer_type == "turnkey":
            sign_with = turnkey_sign_with or os.getenv(ENV_TURNKEY_SIGN_WITH)
            if not sign_with:
                raise ValueError(
                    f"turnkey_sign_with required for Turnkey signing. "
                    f"Set {ENV_TURNKEY_SIGN_WITH} env var."
                )

            address = turnkey_address or os.getenv(ENV_TURNKEY_ADDRESS)

            return TurnkeySigner(sign_with=sign_with, address=address)

        else:
            raise ValueError(f"Unknown signer type: {signer_type}")


# Global signer instance for convenience
_default_signer: Optional[NeoSigner] = None


def get_default_signer() -> NeoSigner:
    """Get the default Neo signer instance."""
    global _default_signer
    if _default_signer is None:
        _default_signer = SignerManager.create_signer()
    return _default_signer


def set_default_signer(signer: NeoSigner):
    """Set the default Neo signer instance."""
    global _default_signer
    _default_signer = signer


def reset_default_signer():
    """Reset the default signer (useful for testing)."""
    global _default_signer
    _default_signer = None
