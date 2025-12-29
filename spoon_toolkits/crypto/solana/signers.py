"""
Unified signer interface for Solana tools supporting both local private key and Turnkey signing.

This module provides a clean abstraction for transaction signing, allowing Solana tools
to work with either local private keys (via solders) or Turnkey's secure API.

Priority order for auto-detection:
1. Plain private key from environment variable (not encrypted)
2. Encrypted private key from SecretVault (ENC:v2 decrypted)
3. Turnkey remote signing
"""

import os
import time
import logging
from abc import ABC, abstractmethod
from typing import Any, Mapping, Optional, Union

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.message import MessageV0
from solders.transaction import VersionedTransaction

from .keypairUtils import _decode_private_key

logger = logging.getLogger(__name__)

# Environment variable keys
ENV_PRIVATE_KEY = "SOLANA_PRIVATE_KEY"
ENV_PRIVATE_KEY_ALT = "WALLET_PRIVATE_KEY"
ENV_TURNKEY_SIGN_WITH = "TURNKEY_SOLANA_ADDRESS"
ENV_TURNKEY_SIGN_WITH_ALT = "TURNKEY_SIGN_WITH"
ENV_TURNKEY_DEFAULT_ADDRESS = "TURNKEY_DEFAULT_ADDRESS"


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


def _get_plain_private_key_from_env() -> Optional[str]:
    """Get plain (non-encrypted) private key from environment variables."""
    for key in (ENV_PRIVATE_KEY, ENV_PRIVATE_KEY_ALT):
        value = os.getenv(key)
        if value and not _is_encrypted(value):
            return value
    return None


def _get_private_key_from_vault() -> Optional[str]:
    """
    Get decrypted private key from SecretVault.

    If an encrypted key exists in env but not in vault, auto-decrypt it first.
    """
    for key in (ENV_PRIVATE_KEY, ENV_PRIVATE_KEY_ALT):
        # Check if already in vault
        value = _get_from_vault(key)
        if value:
            return value

        # Try auto-decrypt if encrypted in env
        env_value = os.getenv(key)
        if env_value and _is_encrypted(env_value):
            if _auto_decrypt_to_vault(key):
                value = _get_from_vault(key)
                if value:
                    return value

    return None


def _get_turnkey_sign_with() -> Optional[str]:
    """Get Turnkey sign_with from environment variables."""
    for key in (ENV_TURNKEY_SIGN_WITH, ENV_TURNKEY_SIGN_WITH_ALT, ENV_TURNKEY_DEFAULT_ADDRESS):
        value = os.getenv(key)
        if value:
            return value
    return None


class SignerError(Exception):
    """Exception raised for signing-related errors."""
    pass


class SolanaSigner(ABC):
    """Abstract base class for Solana transaction signers."""

    @abstractmethod
    def sign_message(self, message: bytes) -> Signature:
        """
        Sign a raw message.

        Args:
            message: The message bytes to sign.

        Returns:
            Solana Signature object.
        """
        pass

    @abstractmethod
    def sign_transaction(self, transaction_message: bytes) -> bytes:
        """
        Sign a Solana transaction message.

        Args:
            transaction_message: Serialized transaction message bytes.

        Returns:
            64-byte Ed25519 signature.
        """
        pass

    @abstractmethod
    def get_address(self) -> str:
        """
        Get the signer's Solana address.

        Returns:
            Base58 encoded address string.
        """
        pass

    @property
    @abstractmethod
    def pubkey(self) -> Pubkey:
        """Return the signer's public key as a Pubkey object."""
        pass

    @property
    @abstractmethod
    def signer_type(self) -> str:
        """Return the type of signer ('local' or 'turnkey')."""
        pass

    def sign_versioned_transaction(
        self,
        message: MessageV0,
        additional_signers: Optional[list] = None
    ) -> VersionedTransaction:
        """
        Sign a versioned transaction with this signer.

        Args:
            message: The MessageV0 to sign.
            additional_signers: Additional Keypair signers if needed.

        Returns:
            Signed VersionedTransaction.
        """
        # This method will be implemented by subclasses that support it
        raise NotImplementedError("Subclass must implement sign_versioned_transaction")


class LocalSigner(SolanaSigner):
    """Signer using local private key via solders."""

    def __init__(self, private_key: str):
        """
        Initialize with private key.

        Args:
            private_key: Private key as base58 or base64 encoded string.
        """
        if not private_key:
            raise ValueError("Private key is required")
        self._keypair = _decode_private_key(private_key)

    @property
    def keypair(self) -> Keypair:
        """Return the underlying Keypair object."""
        return self._keypair

    def sign_message(self, message: bytes) -> Signature:
        """Sign a raw message using local private key."""
        try:
            return self._keypair.sign_message(message)
        except Exception as e:
            raise SignerError(f"Local signing failed: {str(e)}")

    def sign_transaction(self, transaction_message: bytes) -> bytes:
        """Sign transaction message using local private key."""
        try:
            signature = self._keypair.sign_message(transaction_message)
            return bytes(signature)
        except Exception as e:
            raise SignerError(f"Local transaction signing failed: {str(e)}")

    def sign_versioned_transaction(
        self,
        message: MessageV0,
        additional_signers: Optional[list] = None
    ) -> VersionedTransaction:
        """Sign a versioned transaction with this signer."""
        signers = [self._keypair]
        if additional_signers:
            signers.extend(additional_signers)
        return VersionedTransaction(message, signers)

    def get_address(self) -> str:
        """Get the account address."""
        return str(self._keypair.pubkey())

    @property
    def pubkey(self) -> Pubkey:
        """Return the public key."""
        return self._keypair.pubkey()

    @property
    def signer_type(self) -> str:
        return "local"


class TurnkeySigner(SolanaSigner):
    """
    Signer using Turnkey API for secure key management.

    This class directly integrates with Turnkey's MPC signing API for Solana,
    eliminating the need to store private keys locally.
    """

    def __init__(
        self,
        sign_with: str,
        turnkey_client=None,
        organization_id: Optional[str] = None,
        poll_interval: float = 1.0,
        poll_timeout: Optional[float] = 90.0,
    ):
        """
        Initialize with Turnkey signing identity.

        Args:
            sign_with: Turnkey signing identity (Solana address or private key ID).
            turnkey_client: Optional Turnkey client instance, will create if not provided.
            organization_id: Optional organization ID, defaults to env var.
            poll_interval: Seconds between activity status polls.
            poll_timeout: Maximum seconds to wait for signing completion.
        """
        self.sign_with = sign_with
        self._turnkey_client = turnkey_client
        self._organization_id = organization_id
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout
        self._client = None

    def _get_client(self):
        """Lazy initialization of Turnkey client."""
        if self._client is None:
            try:
                from spoon_ai.turnkey import Turnkey
                self._client = self._turnkey_client or Turnkey()
                if self._organization_id is None:
                    self._organization_id = self._client.org_id
            except ImportError as e:
                raise SignerError(
                    f"Turnkey dependencies not available: {str(e)}. "
                    "Please install spoon_ai with Turnkey support."
                )
            except Exception as e:
                raise SignerError(f"Failed to initialize Turnkey client: {str(e)}")
        return self._client

    def sign_message(self, message: bytes) -> Signature:
        """
        Sign a message using Turnkey.

        For Solana (Ed25519), we use raw payload signing with NO_OP hash function
        since Ed25519 doesn't pre-hash the message.

        Args:
            message: The message bytes to sign.

        Returns:
            Solana Signature object.
        """
        try:
            client = self._get_client()

            # Encode message as hex for Turnkey API
            payload_hex = message.hex()

            response = client._sign_raw_payload(
                sign_with=self.sign_with,
                payload=payload_hex,
                encoding="PAYLOAD_ENCODING_HEXADECIMAL",
                hash_function="HASH_FUNCTION_NO_OP",  # Ed25519 doesn't pre-hash
            )

            inline_result = self._extract_result(response, "signRawPayloadResult")
            activity_id = self._extract_activity_id(response)

            result = inline_result
            if not result or not result.get("r"):
                activity = self._poll_activity(activity_id, "Solana message signing")
                result = self._extract_result(activity, "signRawPayloadResult")

            return self._parse_solana_signature(result)
        except SignerError:
            raise
        except Exception as e:
            raise SignerError(f"Turnkey message signing failed: {str(e)}")

    def sign_transaction(self, transaction_message: bytes) -> bytes:
        """Sign transaction message using Turnkey API."""
        signature = self.sign_message(transaction_message)
        return bytes(signature)

    def sign_versioned_transaction(
        self,
        message: MessageV0,
        additional_signers: Optional[list] = None
    ) -> VersionedTransaction:
        """
        Sign a versioned transaction using Turnkey.

        Note: Turnkey signing requires serializing the message first,
        then reconstructing the transaction with the signature.
        """
        try:
            # Serialize the message
            message_bytes = bytes(message)

            # Sign using Turnkey
            signature_bytes = self.sign_transaction(message_bytes)
            signature = Signature.from_bytes(signature_bytes)

            # Build signed transaction
            from solders.transaction import VersionedTransaction as VTx

            # Create signature list with Turnkey signature first
            signatures = [signature]

            # Add signatures from additional signers
            if additional_signers:
                for signer in additional_signers:
                    sig = signer.sign_message(message_bytes)
                    signatures.append(sig)

            return VTx.populate(message, signatures)
        except SignerError:
            raise
        except Exception as e:
            raise SignerError(f"Turnkey versioned transaction signing failed: {str(e)}")

    def get_address(self) -> str:
        """Get the signing address."""
        return self.sign_with

    @property
    def pubkey(self) -> Pubkey:
        """Return the public key."""
        return Pubkey.from_string(self.sign_with)

    @property
    def signer_type(self) -> str:
        return "turnkey"

    def _parse_solana_signature(self, result: Mapping[str, Any]) -> Signature:
        """
        Parse Turnkey signature result into Solana Signature.

        Turnkey returns r and s components for Ed25519 signatures.
        For Ed25519, the signature is simply r || s (64 bytes total).
        """
        if not isinstance(result, Mapping):
            raise SignerError("Turnkey signature response malformed.")

        # Check for direct signature first
        signature_hex = result.get("signature") or result.get("signatureHex")
        if signature_hex:
            sig_bytes = bytes.fromhex(signature_hex.replace("0x", ""))
            if len(sig_bytes) == 64:
                return Signature.from_bytes(sig_bytes)

        # Otherwise, reconstruct from r and s
        r_hex = result.get("r", "")
        s_hex = result.get("s", "")

        if not r_hex or not s_hex:
            raise SignerError("Turnkey signature missing r or s components.")

        # Remove 0x prefix if present
        r_hex = r_hex.replace("0x", "")
        s_hex = s_hex.replace("0x", "")

        # Pad to 32 bytes each
        r_bytes = bytes.fromhex(r_hex.zfill(64))
        s_bytes = bytes.fromhex(s_hex.zfill(64))

        # Ed25519 signature is r || s
        signature_bytes = r_bytes + s_bytes

        if len(signature_bytes) != 64:
            raise SignerError(f"Invalid signature length: {len(signature_bytes)}, expected 64")

        return Signature.from_bytes(signature_bytes)

    def _extract_activity_id(self, response: Mapping[str, Any]) -> str:
        """Extract activity ID from Turnkey response."""
        activity = response.get("activity") if isinstance(response, Mapping) else None
        if not activity:
            raise SignerError("Turnkey response missing activity payload.")
        activity_id = activity.get("id") or activity.get("activityId")
        if not activity_id:
            raise SignerError("Turnkey response missing activity id.")
        return activity_id

    def _poll_activity(self, activity_id: str, description: str) -> Mapping[str, Any]:
        """Poll Turnkey activity until completion."""
        client = self._get_client()
        start = time.time()
        while True:
            activity_resp = client.get_activity(activity_id)
            activity = activity_resp.get("activity", {})
            status = activity.get("status")

            if status == "ACTIVITY_STATUS_COMPLETED":
                return activity
            if status in {"ACTIVITY_STATUS_FAILED", "ACTIVITY_STATUS_REJECTED"}:
                raise SignerError(f"Turnkey {description} failed with status {status}")
            if self.poll_timeout and (time.time() - start) > self.poll_timeout:
                raise SignerError(f"Timed out waiting for Turnkey to complete {description}.")

            time.sleep(self.poll_interval)

    def _extract_result(
        self, payload: Mapping[str, Any], result_key: str
    ) -> Mapping[str, Any]:
        """Extract result from Turnkey response payload."""
        if not isinstance(payload, Mapping):
            return {}
        result_root = (
            payload.get("result")
            or payload.get("activity", {}).get("result")
            or {}
        )
        if not isinstance(result_root, Mapping):
            return {}
        specific = result_root.get(result_key)
        if isinstance(specific, Mapping):
            return specific
        if not specific and result_root:
            return result_root
        return {}


class SignerManager:
    """Manager for creating and configuring Solana signers."""

    @staticmethod
    def create_signer(
        signer_type: str = "auto",
        private_key: Optional[str] = None,
        turnkey_sign_with: Optional[str] = None,
        turnkey_client=None,
        turnkey_organization_id: Optional[str] = None,
    ) -> SolanaSigner:
        """
        Create a signer based on configuration.

        Priority order for auto-detection:
        1. Plain private key from env (not encrypted)
        2. Encrypted private key from SecretVault
        3. Turnkey remote signing

        Args:
            signer_type: 'local', 'turnkey', or 'auto'.
            private_key: Private key for local signing (base58 or base64).
            turnkey_sign_with: Turnkey signing identity (Solana address or key ID).
            turnkey_client: Optional Turnkey client instance.
            turnkey_organization_id: Optional Turnkey organization ID.

        Returns:
            Configured signer instance.
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

                # 1. Plain private key from env (not encrypted)
                if _get_plain_private_key_from_env():
                    signer_type = "local"

                # 2. Encrypted private key from SecretVault
                elif _get_private_key_from_vault():
                    signer_type = "local"

                # 3. Turnkey remote signing
                elif _get_turnkey_sign_with():
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
                key = _get_plain_private_key_from_env()
            if not key:
                key = _get_private_key_from_vault()

            if not key:
                raise ValueError(
                    f"Private key required for local signing. "
                    f"Set {ENV_PRIVATE_KEY} or decrypt encrypted key to vault."
                )
            return LocalSigner(key)

        elif signer_type == "turnkey":
            sign_with = turnkey_sign_with or _get_turnkey_sign_with()
            if not sign_with:
                raise ValueError(
                    f"turnkey_sign_with required for Turnkey signing. "
                    f"Set {ENV_TURNKEY_SIGN_WITH} env var."
                )

            return TurnkeySigner(
                sign_with=sign_with,
                turnkey_client=turnkey_client,
                organization_id=turnkey_organization_id,
            )

        else:
            raise ValueError(f"Unknown signer type: {signer_type}")


# Global signer instance for convenience
_default_signer: Optional[SolanaSigner] = None


def get_default_signer() -> SolanaSigner:
    """Get the default signer instance."""
    global _default_signer
    if _default_signer is None:
        _default_signer = SignerManager.create_signer()
    return _default_signer


def set_default_signer(signer: SolanaSigner):
    """Set the default signer instance."""
    global _default_signer
    _default_signer = signer


def has_signer_credentials() -> bool:
    """Check if any signer credentials are configured."""
    # Check for local key
    if _get_plain_private_key_from_env() or _get_private_key_from_vault():
        return True

    # Check for Turnkey credentials
    turnkey_required = ("TURNKEY_API_PUBLIC_KEY", "TURNKEY_API_PRIVATE_KEY", "TURNKEY_ORG_ID")
    has_turnkey = all(os.getenv(k) for k in turnkey_required)
    has_turnkey_address = bool(_get_turnkey_sign_with())

    return has_turnkey and has_turnkey_address


__all__ = [
    "SignerError",
    "SolanaSigner",
    "LocalSigner",
    "TurnkeySigner",
    "SignerManager",
    "get_default_signer",
    "set_default_signer",
    "has_signer_credentials",
]
