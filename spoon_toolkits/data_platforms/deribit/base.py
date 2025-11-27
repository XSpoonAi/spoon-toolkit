"""Base tool class for Deribit tools"""

import logging
from typing import Any, Dict, Optional
from pydantic import Field

try:
    from spoon_ai.tools.base import BaseTool, ToolResult
except ImportError:
    # Fallback for development/testing
    from typing import TypedDict, Dict, Any
    from abc import ABC, abstractmethod
    from pydantic import BaseModel, Field
    
    class ToolResult(TypedDict, total=False):
        output: Optional[Any]
        error: Optional[str]
    
    class BaseTool(ABC, BaseModel):
        """Base tool class (fallback when spoon_ai is not available)"""
        name: str = Field(description="The name of the tool")
        description: str = Field(description="A description of the tool")
        parameters: dict = Field(default_factory=dict, description="The parameters of the tool")
        
        model_config = {"arbitrary_types_allowed": True}
        
        @abstractmethod
        async def execute(self, **kwargs) -> ToolResult:
            """Execute the tool"""
            raise NotImplementedError("Subclasses must implement execute method")

from .jsonrpc_client import DeribitJsonRpcClient
from .auth import DeribitAuth

logger = logging.getLogger(__name__)


class DeribitBaseTool(BaseTool):
    """Base class for all Deribit tools"""
    
    # Internal fields (not part of Pydantic model)
    _jsonrpc_client: Optional[DeribitJsonRpcClient] = None
    _auth: Optional[DeribitAuth] = None
    _client_initialized: bool = False
    
    def __init__(self, **kwargs):
        """Initialize Deribit base tool"""
        super().__init__(**kwargs)
        
        # Lazy initialization - will be created on first use
        self._client_initialized = False
    
    @property
    def jsonrpc_client(self) -> Optional[DeribitJsonRpcClient]:
        """Get JSON-RPC client (lazy initialization)"""
        return self._jsonrpc_client
    
    @property
    def auth(self) -> Optional[DeribitAuth]:
        """Get auth manager (lazy initialization)"""
        return self._auth
    
    def _ensure_client(self):
        """Ensure JSON-RPC client and auth are initialized"""
        if not self._client_initialized:
            self._jsonrpc_client = DeribitJsonRpcClient()
            self._auth = DeribitAuth(jsonrpc_client=self._jsonrpc_client)
            self._client_initialized = True
    
    async def _ensure_authenticated(self):
        """Ensure we have a valid authentication token"""
        self._ensure_client()
        if self._auth:
            await self._auth.ensure_authenticated()
            # Update client with latest token
            if self._auth.get_access_token():
                self._jsonrpc_client.set_access_token(self._auth.get_access_token())
    
    async def _call_public_method(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Call a public API method (no authentication required)
        
        Args:
            method: JSON-RPC method name
            params: Method parameters
            
        Returns:
            API response result
        """
        self._ensure_client()
        return await self._jsonrpc_client.call(method, params)
    
    async def _call_private_method(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Call a private API method (authentication required)
        
        Args:
            method: JSON-RPC method name
            params: Method parameters
            
        Returns:
            API response result
        """
        await self._ensure_authenticated()
        return await self._jsonrpc_client.call(method, params)
    
    async def execute(self, **kwargs) -> ToolResult:
        """
        Execute the tool (to be implemented by subclasses)
        
        Args:
            **kwargs: Tool-specific parameters
            
        Returns:
            ToolResult with output or error
        """
        raise NotImplementedError("Subclasses must implement execute method")
    
    async def __aenter__(self):
        """Async context manager entry"""
        self._ensure_client()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self._jsonrpc_client:
            await self._jsonrpc_client.close()

