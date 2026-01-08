"""OAuth2 authentication for Deribit API"""

import logging
import time
from typing import Dict, Optional
from .jsonrpc_client import DeribitJsonRpcClient, DeribitJsonRpcError
from .env import DeribitConfig

logger = logging.getLogger(__name__)


class DeribitAuthError(Exception):
    """Exception for Deribit authentication errors"""
    pass


class DeribitAuth:
    """OAuth2 authentication manager for Deribit API"""
    
    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        jsonrpc_client: Optional[DeribitJsonRpcClient] = None
    ):
        """
        Initialize authentication manager
        
        Args:
            client_id: Deribit client ID (defaults to config)
            client_secret: Deribit client secret (defaults to config)
            jsonrpc_client: JSON-RPC client instance (creates new if not provided)
        """
        if client_id and client_secret:
            self.client_id = client_id
            self.client_secret = client_secret
        else:
            # Lazy credential loading - only get when needed
            self.client_id = None
            self.client_secret = None
        
        self.jsonrpc_client = jsonrpc_client or DeribitJsonRpcClient()
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[float] = None
        self.scope: Optional[str] = None
    
    def _ensure_credentials(self):
        """Ensure credentials are loaded"""
        if not self.client_id or not self.client_secret:
            self.client_id, self.client_secret = DeribitConfig.get_credentials()
    
    async def authenticate(
        self,
        grant_type: str = "client_credentials",
        scope: Optional[str] = None
    ) -> Dict[str, any]:
        """
        Authenticate and get access token
        
        Args:
            grant_type: OAuth2 grant type (default: "client_credentials")
            scope: Access scope (e.g., "account:read trade:read_write")
            
        Returns:
            Authentication response with access_token, refresh_token, etc.
            
        Raises:
            DeribitAuthError: If authentication fails
        """
        # Load credentials if not already loaded
        self._ensure_credentials()
        
        try:
            params = {
                "grant_type": grant_type,
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
            
            if scope:
                params["scope"] = scope
            
            logger.info("Authenticating with Deribit API...")
            result = await self.jsonrpc_client.call("public/auth", params)
            
            # Store tokens
            self.access_token = result.get("access_token")
            self.refresh_token = result.get("refresh_token")
            self.scope = result.get("scope")
            
            # Calculate expiration time (expires_in is in seconds)
            expires_in = result.get("expires_in", 3600)
            self.token_expires_at = time.time() + expires_in - 60  # 1 minute buffer
            
            # Set token in JSON-RPC client
            if self.access_token:
                self.jsonrpc_client.set_access_token(self.access_token)
            
            logger.info("Authentication successful")
            return result
            
        except DeribitJsonRpcError as e:
            error_msg = f"Authentication failed: {str(e)}"
            logger.error(error_msg)
            raise DeribitAuthError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected authentication error: {str(e)}"
            logger.error(error_msg)
            raise DeribitAuthError(error_msg) from e
    
    async def refresh_access_token(self) -> Dict[str, any]:
        """
        Refresh access token using refresh_token
        
        Returns:
            New authentication response
            
        Raises:
            DeribitAuthError: If refresh fails
        """
        if not self.refresh_token:
            # If no refresh token, re-authenticate
            return await self.authenticate()
        
        try:
            params = {
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token
            }
            
            logger.info("Refreshing access token...")
            result = await self.jsonrpc_client.call("public/auth", params)
            
            # Update tokens
            self.access_token = result.get("access_token")
            self.refresh_token = result.get("refresh_token", self.refresh_token)
            
            # Calculate expiration time
            expires_in = result.get("expires_in", 3600)
            self.token_expires_at = time.time() + expires_in - 60
            
            # Update token in JSON-RPC client
            if self.access_token:
                self.jsonrpc_client.set_access_token(self.access_token)
            
            logger.info("Token refreshed successfully")
            return result
            
        except DeribitJsonRpcError as e:
            error_msg = f"Token refresh failed: {str(e)}"
            logger.error(error_msg)
            # Try to re-authenticate
            logger.info("Attempting to re-authenticate...")
            return await self.authenticate()
        except Exception as e:
            error_msg = f"Unexpected refresh error: {str(e)}"
            logger.error(error_msg)
            raise DeribitAuthError(error_msg) from e
    
    def is_token_valid(self) -> bool:
        """Check if current access token is valid (not expired)"""
        if not self.access_token or not self.token_expires_at:
            return False
        return time.time() < self.token_expires_at
    
    async def ensure_authenticated(self):
        """Ensure we have a valid access token, refresh if needed"""
        if not self.is_token_valid():
            if self.refresh_token:
                await self.refresh_access_token()
            else:
                await self.authenticate()
    
    def get_access_token(self) -> Optional[str]:
        """Get current access token"""
        return self.access_token
    
    def logout(self):
        """Logout and clear tokens"""
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None
        self.scope = None
        self.jsonrpc_client.clear_access_token()
        logger.info("Logged out")

