"""JSON-RPC 2.0 client for Deribit API"""

import asyncio
import logging
import uuid
import json
from typing import Any, Dict, Optional
import httpx
from .env import DeribitConfig

logger = logging.getLogger(__name__)


class DeribitJsonRpcError(Exception):
    """Base exception for Deribit JSON-RPC errors"""
    pass


class DeribitJsonRpcClient:
    """JSON-RPC 2.0 client for Deribit API"""
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Optional[int] = None,
        access_token: Optional[str] = None
    ):
        """
        Initialize JSON-RPC client
        
        Args:
            base_url: API base URL (defaults to config)
            timeout: Request timeout in seconds (defaults to config)
            access_token: OAuth2 access token
        """
        self.base_url = base_url or DeribitConfig.get_api_url()
        self.timeout = timeout or DeribitConfig.TIMEOUT
        self.access_token = access_token
        self.session: Optional[httpx.AsyncClient] = None
        self._request_id = 0
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = httpx.AsyncClient(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.aclose()
    
    def _generate_id(self) -> int:
        """Generate unique request ID"""
        self._request_id += 1
        return self._request_id
    
    def set_access_token(self, token: str):
        """Set OAuth2 access token"""
        self.access_token = token
    
    def clear_access_token(self):
        """Clear OAuth2 access token"""
        self.access_token = None
    
    async def call(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        retry_count: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Call JSON-RPC method
        
        Args:
            method: JSON-RPC method name (e.g., "public/get_instruments")
            params: Method parameters
            retry_count: Number of retry attempts (defaults to config)
            
        Returns:
            JSON-RPC response result
            
        Raises:
            DeribitJsonRpcError: If API call fails
        """
        if not self.session:
            self.session = httpx.AsyncClient(timeout=self.timeout)
        
        retry_count = retry_count or DeribitConfig.RETRY_COUNT
        params = params or {}
        
        request = {
            "jsonrpc": "2.0",
            "id": self._generate_id(),
            "method": method,
            "params": params
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        
        last_error = None
        
        for attempt in range(retry_count + 1):
            try:
                logger.debug(f"Calling {method} (attempt {attempt + 1}/{retry_count + 1})")
                
                response = await self.session.post(
                    self.base_url,
                    json=request,
                    headers=headers
                )
                response.raise_for_status()
                
                result = response.json()
                
                # Check for JSON-RPC error
                if "error" in result:
                    error = result["error"]
                    error_code = error.get("code", -1)
                    error_message = error.get("message", "Unknown error")
                    error_data = error.get("data", {})
                    
                    # Build detailed error message
                    detailed_error = f"API error {error_code}: {error_message}"
                    if error_data:
                        if isinstance(error_data, dict):
                            detailed_error += f" | Data: {json.dumps(error_data, ensure_ascii=False)}"
                        else:
                            detailed_error += f" | Data: {error_data}"
                    
                    # Don't retry on client errors (4xx)
                    if 400 <= error_code < 500:
                        raise DeribitJsonRpcError(detailed_error)
                    
                    # Retry on server errors (5xx) or network errors
                    if attempt < retry_count:
                        logger.warning(
                            f"API error {error_code}: {error_message}. "
                            f"Retrying... ({attempt + 1}/{retry_count})"
                        )
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        continue
                    
                    raise DeribitJsonRpcError(
                        f"API error {error_code}: {error_message}"
                    )
                
                # Return result
                if "result" in result:
                    return result["result"]
                else:
                    raise DeribitJsonRpcError("Response missing 'result' field")
                    
            except httpx.HTTPStatusError as e:
                # HTTP error with status code
                last_error = e
                # Try to get error details from response
                error_details = ""
                try:
                    if e.response is not None:
                        response_text = e.response.text
                        error_details = f" | Response: {response_text[:500]}"
                except:
                    pass
                
                if attempt < retry_count:
                    logger.warning(
                        f"HTTP error: {e}{error_details}. Retrying... ({attempt + 1}/{retry_count})"
                    )
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise DeribitJsonRpcError(f"HTTP error: {str(e)}{error_details}")
            except httpx.HTTPError as e:
                last_error = e
                if attempt < retry_count:
                    logger.warning(
                        f"HTTP error: {e}. Retrying... ({attempt + 1}/{retry_count})"
                    )
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise DeribitJsonRpcError(f"HTTP error: {str(e)}")
            
            except Exception as e:
                last_error = e
                if attempt < retry_count:
                    logger.warning(
                        f"Unexpected error: {e}. Retrying... ({attempt + 1}/{retry_count})"
                    )
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise DeribitJsonRpcError(f"Unexpected error: {str(e)}")
        
        # If we get here, all retries failed
        raise DeribitJsonRpcError(
            f"Failed after {retry_count + 1} attempts. Last error: {last_error}"
        )
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.aclose()
            self.session = None

