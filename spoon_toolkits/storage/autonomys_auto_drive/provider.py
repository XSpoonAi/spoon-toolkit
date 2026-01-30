"""Autonomys Auto Drive provider - File Upload Focused"""

import os
import httpx
import json
import asyncio
from typing import Dict, Any, Optional, Union
import logging

logger = logging.getLogger(__name__)

class AutoDriveAPIError(Exception):
    """Exception raised for errors in the Auto Drive API."""
    def __init__(self, message: str, status_code: int = None, response_body: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body

def mask_token(token: str, show_chars: int = 8) -> str:
    """Mask token for logging (show first N chars)"""
    if not token or len(token) <= show_chars:
        return "***"
    return token[:show_chars] + "..." + token[-4:] if len(token) > show_chars + 4 else token[:show_chars] + "***"

def mask_response(response_data: Any) -> Any:
    """Mask sensitive data in response for logging"""
    if isinstance(response_data, dict):
        masked = {}
        for key, value in response_data.items():
            if 'token' in key.lower() or 'key' in key.lower() or 'secret' in key.lower():
                masked[key] = mask_token(str(value)) if value else value
            elif isinstance(value, (dict, list)):
                masked[key] = mask_response(value)
            else:
                masked[key] = value
        return masked
    elif isinstance(response_data, list):
        return [mask_response(item) for item in response_data]
    return response_data

class AutoDriveProvider:
    """Autonomys Auto Drive API provider - File Upload Focused"""

    def __init__(self, api_key: str, auth_provider: str = "apikey", base_url: str = "https://mainnet.auto-drive.autonomys.xyz", debug: bool = True):
        if not api_key:
            raise ValueError("AUTONOMYS_AUTO_DRIVE_API_KEY is required but not provided.")
            
        self.api_key = api_key
        self.auth_provider = auth_provider  # User-configurable, not hardcoded
        self.base_url = base_url.rstrip('/')
        self.debug = debug
        
        self.headers = {
            'Authorization': f"Bearer {self.api_key}",
            'X-Auth-Provider': self.auth_provider,
            'Accept': 'application/json'
        }
        
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.headers,
            timeout=120.0 
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

    async def aclose(self):
        """Explicitly close the HTTP client session"""
        await self.client.aclose()

    def _get_default_upload_options(self):
        """Returns standard upload options as per official API schema"""
        return {
            "compression": {
                "algorithm": "ZLIB",
                "level": 8
            },
            "encryption": {
                "algorithm": "AES_256_GCM",
                "chunkSize": 1024
            }
        }

    def _log_request(self, method: str, url: str, status_code: int = None, response_data: Any = None, request_data: Any = None):
        """Log request/response for debugging"""
        if not self.debug:
            return
            
        print(f"\n{'='*80}")
        print(f"[DEBUG] {method} {url}")
        if status_code:
            print(f"Status: {status_code}")
        if request_data:
            print(f"Request Body: {json.dumps(mask_response(request_data), indent=2, ensure_ascii=False)}")
        if response_data:
            print(f"Response: {json.dumps(mask_response(response_data), indent=2, ensure_ascii=False)}")
        print(f"{'='*80}\n")

    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Any:
        """
        Make an HTTP request to the Auto Drive API.
        All endpoints use /api prefix.
        """
        path = endpoint.lstrip('/')
        
        # If endpoint already starts with 'api/', use it as-is
        if path.startswith('api/'):
            full_endpoint = f"/{path}"
        # Otherwise, add /api prefix
        else:
            full_endpoint = f"/api/{path}"
        
        full_url = f"{self.base_url}{full_endpoint}"
        request_data = kwargs.get('json') or kwargs.get('data')
        
        try:
            response = await self.client.request(method, full_endpoint, **kwargs)
            
            response_data = None
            try:
                if response.status_code != 204:
                    response_data = response.json()
            except:
                response_data = response.text
            
            self._log_request(method, full_url, response.status_code, response_data, request_data)
            
            if response.status_code >= 400:
                error_data = response_data
                message = error_data.get('error', error_data.get('message', response.text)) if isinstance(error_data, dict) else str(error_data)
                
                error_msg = f"{response.reason_phrase}: {message}"
                if error_data:
                    error_msg += f" | Details: {error_data}"
                    
                raise AutoDriveAPIError(error_msg, status_code=response.status_code, response_body=error_data)
            
            if response.status_code == 204:
                return None
                
            return response_data
        except httpx.HTTPError as e:
            self._log_request(method, full_url, None, None, request_data)
            raise AutoDriveAPIError(f"Network Error: {str(e)}")
        except AutoDriveAPIError:
            raise
        except Exception as e:
            self._log_request(method, full_url, None, None, request_data)
            raise AutoDriveAPIError(f"Request Error: {str(e)}")

    # --- File Upload Methods ---

    async def upload_file_small(
        self, 
        content_or_path: Union[bytes, str], 
        filename: str, 
        mime_type: str = "application/octet-stream",
        upload_options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Upload a small file directly.
        
        Args:
            content_or_path: File content as bytes or file path string
            filename: Name of the file
            mime_type: MIME type of the file
            upload_options: Optional upload options (compression, encryption)
        
        Returns:
            Upload result with CID and metadata
        """
        # Read content if path provided
        if isinstance(content_or_path, str):
            if not os.path.isfile(content_or_path):
                raise FileNotFoundError(f"File not found: {content_or_path}")
            with open(content_or_path, 'rb') as f:
                content = f.read()
        else:
            content = content_or_path
        
        upload_opts = upload_options or self._get_default_upload_options()
        
        # Step 1: POST /api/uploads/file - Create upload session
        init_data = {
            "filename": filename,
            "mimeType": mime_type,
            "uploadOptions": upload_opts
        }
        init_res = await self._make_request("POST", "/api/uploads/file", json=init_data)
        upload_id = init_res.get('id') or init_res.get('uploadId')
        
        if not upload_id:
            raise AutoDriveAPIError(f"Failed to get upload_id for file: {init_res}", response_body=init_res)

        # Step 2: POST /api/uploads/file/{upload_id}/chunk - Upload file content
        files = {'file': (filename, content, mime_type)}
        data = {'index': '0'}
        await self._make_request("POST", f"/api/uploads/file/{upload_id}/chunk", files=files, data=data)

        # Step 3: POST /api/uploads/{upload_id}/complete - Complete upload
        complete_res = await self._make_request("POST", f"/api/uploads/{upload_id}/complete")
        
        return complete_res

    async def upload_file_large(
        self,
        file_path: str,
        chunk_size: int = 5 * 1024 * 1024,  # 5MB default
        concurrency: int = 1,  # API requires sequential upload, so concurrency must be 1
        retry: int = 3,
        resume: bool = True
    ) -> Dict[str, Any]:
        """
        Upload a large file with chunking, concurrency, retry, and resume support.
        
        Args:
            file_path: Path to the file to upload
            chunk_size: Size of each chunk in bytes (default: 5MB)
            concurrency: Number of concurrent chunk uploads (default: 3)
            retry: Number of retry attempts for failed chunks (default: 3)
            resume: Whether to resume interrupted uploads (default: True)
        
        Returns:
            Upload result with CID and metadata
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        _, suffix = os.path.splitext(file_path)
        
        # Get MIME type
        try:
            from spoon_toolkits.storage.autonomys_auto_drive.mime_type import suffix_to_mime_type_dict
            mime_type = suffix_to_mime_type_dict.get(suffix, 'application/octet-stream')
        except (ImportError, AttributeError):
            # Fallback if mime_type module not available
            mime_type = 'application/octet-stream'
        
        upload_id = None
        uploaded_parts = set()
        
        # Step 1: POST /api/uploads/file - Create upload session (or resume)
        if resume:
            # Try to get existing upload status
            # Note: This requires GET /api/objects/{upload_id}/status endpoint
            # For now, we'll create a new session
            pass
        
        init_data = {
            "filename": filename,
            "mimeType": mime_type,
            "uploadOptions": self._get_default_upload_options()
        }
        
        # Use /api/uploads/file endpoint for all files (both small and large)
        # Large files are handled by uploading multiple chunks
        init_res = await self._make_request("POST", "/api/uploads/file", json=init_data)
        upload_id = init_res.get('id') or init_res.get('uploadId')
        
        if not upload_id:
            raise AutoDriveAPIError(f"Failed to get upload_id: {init_res}", response_body=init_res)
        
        print(f"\n[UPLOAD] Starting upload: {filename} ({file_size} bytes)")
        print(f"[UPLOAD] Upload ID: {upload_id}")
        print(f"[UPLOAD] Chunk size: {chunk_size} bytes")
        if concurrency > 1:
            print(f"[UPLOAD] Warning: API requires sequential upload, concurrency={concurrency} will be ignored")
        
        # Step 2: Upload chunks sequentially (API requires sequential upload)
        # Note: API requires chunks to be uploaded in order (0, 1, 2, ...)
        # Concurrency is not supported for chunk uploads
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        
        async def upload_chunk(part_index: int, chunk_data: bytes) -> bool:
            """Upload a single chunk with retry"""
            for attempt in range(retry):
                try:
                    files = {'file': ('blob', chunk_data, "application/octet-stream")}
                    data = {'index': str(part_index)}
                    
                    # Use /chunk endpoint
                    await self._make_request("POST", f"/api/uploads/file/{upload_id}/chunk", files=files, data=data)
                    
                    progress = (part_index + 1) / total_chunks * 100
                    print(f"[UPLOAD] Chunk {part_index + 1}/{total_chunks} uploaded ({progress:.1f}%)")
                    return True
                except Exception as e:
                    if attempt < retry - 1:
                        print(f"[UPLOAD] Chunk {part_index + 1} failed (attempt {attempt + 1}/{retry}): {e}, retrying...")
                        await asyncio.sleep(1 * (attempt + 1))  # Exponential backoff
                    else:
                        print(f"[UPLOAD] Chunk {part_index + 1} failed after {retry} attempts: {e}")
                        raise
            return False
        
        # Read and upload chunks sequentially
        with open(file_path, 'rb') as f:
            part_index = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                if part_index not in uploaded_parts:
                    await upload_chunk(part_index, chunk)
                part_index += 1
        
        # Step 3: POST /api/uploads/{upload_id}/complete - Complete upload
        print(f"[UPLOAD] All chunks uploaded, completing...")
        complete_res = await self._make_request("POST", f"/api/uploads/{upload_id}/complete")
        
        print(f"[UPLOAD] Upload completed successfully!")
        return complete_res

    # --- Account Methods ---

    async def get_account_info(self) -> Dict[str, Any]:
        """
        GET /api/accounts/@me - Get current user account information
        
        Returns:
            Account information including subscription details, limits and credits
        """
        return await self._make_request("GET", "/api/accounts/@me")

    # --- Object Management Methods ---

    async def get_root_objects(self, limit: int = 10, offset: int = 0, scope: str = "user") -> Dict[str, Any]:
        """
        GET /api/objects/roots - Get root objects
        
        Args:
            limit: Maximum number of objects to return
            offset: Number of objects to skip
            scope: Scope of objects to retrieve - "global" or "user" (default: "user")
        
        Returns:
            List of root objects
        """
        params = {"limit": limit, "offset": offset, "scope": scope}
        return await self._make_request("GET", "/api/objects/roots", params=params)

    async def search_objects(self, query: str, limit: int = 10, scope: str = "user") -> Dict[str, Any]:
        """
        GET /api/objects/search - Search for objects by CID or name
        
        Args:
            query: Search query (CID or name)
            limit: Maximum number of results to return
            scope: Scope of the search - "global" or "user" (default: "user")
        
        Returns:
            Search results
        """
        params = {"cid": query, "limit": limit, "scope": scope}
        return await self._make_request("GET", "/api/objects/search", params=params)

    async def get_shared_root_objects(self, limit: int = 10, offset: int = 0) -> Dict[str, Any]:
        """
        GET /api/objects/shared/roots - Get shared root objects
        
        Args:
            limit: Maximum number of objects to return
            offset: Number of objects to skip
        
        Returns:
            List of shared root objects
        """
        params = {"limit": limit, "offset": offset}
        return await self._make_request("GET", "/api/objects/roots/shared", params=params)

    async def get_deleted_root_objects(self, limit: int = 10, offset: int = 0) -> Dict[str, Any]:
        """
        GET /api/objects/deleted/roots - Get deleted root objects
        
        Args:
            limit: Maximum number of objects to return
            offset: Number of objects to skip
        
        Returns:
            List of deleted root objects
        """
        params = {"limit": limit, "offset": offset}
        return await self._make_request("GET", "/api/objects/roots/deleted", params=params)

    async def get_object_summary(self, cid: str) -> Dict[str, Any]:
        """
        GET /api/objects/{cid}/summary - Get summary of an object by CID
        
        Args:
            cid: Content Identifier (CID) of the object
        
        Returns:
            Object summary information
        """
        return await self._make_request("GET", f"/api/objects/{cid}/summary")

    async def share_object(self, cid: str, public_id: str) -> Dict[str, Any]:
        """
        POST /api/objects/{cid}/share - Share an object by CID
        
        Args:
            cid: Content Identifier (CID) of the object to share
            public_id: Public ID for the shared object
        
        Returns:
            Response indicating successful sharing
        """
        data = {"publicId": public_id}
        return await self._make_request("POST", f"/api/objects/{cid}/share", json=data)

    # --- Upload Status and Metadata Methods ---

    async def get_upload_status(self, upload_id: str) -> Dict[str, Any]:
        """
        GET /api/objects/{upload_id}/status - Get upload status for resume support
        
        Args:
            upload_id: The upload session ID
        
        Returns:
            Upload status including uploaded parts/chunks
        """
        # Try different possible endpoints
        endpoints = [
            f"/api/objects/{upload_id}/status",
            f"/api/uploads/{upload_id}/status",
            f"/api/uploads/{upload_id}",
        ]
        
        for endpoint in endpoints:
            try:
                return await self._make_request("GET", endpoint)
            except AutoDriveAPIError as e:
                if e.status_code != 404:
                    raise
                continue
        
        raise AutoDriveAPIError(f"Upload status endpoint not found for {upload_id}")

    async def get_object_status(self, cid: str) -> Dict[str, Any]:
        """
        GET /api/objects/{cid}/status - Get object status
        
        Args:
            cid: Content Identifier (CID) of the object
        
        Returns:
            Object status information
        """
        return await self._make_request("GET", f"/api/objects/{cid}/status")

    async def get_object_metadata(self, cid: str) -> Dict[str, Any]:
        """
        GET /api/objects/{cid}/metadata - Get object metadata
        
        Args:
            cid: Content Identifier (CID) of the object
        
        Returns:
            Object metadata
        """
        endpoints = [
            f"/api/objects/{cid}/metadata",
            f"/api/objects/{cid}",
        ]
        
        for endpoint in endpoints:
            try:
                return await self._make_request("GET", endpoint)
            except AutoDriveAPIError as e:
                if e.status_code != 404:
                    raise
                continue
        
        raise AutoDriveAPIError(f"Metadata endpoint not found for CID {cid}")

    async def publish_object(self, cid: str) -> Dict[str, Any]:
        """
        POST /api/objects/{cid}/publish - Publish an object by CID and return the object id
        
        Args:
            cid: Content Identifier (CID) of the object to publish
        
        Returns:
            Response containing the object ID (result field)
        """
        return await self._make_request("POST", f"/api/objects/{cid}/publish")

    async def unpublish_object(self, cid: str) -> None:
        """
        POST /api/objects/{cid}/unpublish - Unpublish an object by CID
        
        Args:
            cid: Content Identifier (CID) of the object to unpublish
        
        Returns:
            None (204 No Content on success)
        """
        return await self._make_request("POST", f"/api/objects/{cid}/unpublish")

    async def delete_object(self, cid: str) -> Dict[str, Any]:
        """
        POST /api/objects/{cid}/delete - Delete an object by CID
        
        Args:
            cid: Content Identifier (CID) of the object to delete
        
        Returns:
            Response indicating successful deletion
        """
        return await self._make_request("POST", f"/api/objects/{cid}/delete")

    async def restore_object(self, cid: str) -> Dict[str, Any]:
        """
        POST /api/objects/{cid}/restore - Restore a deleted object by CID
        
        Args:
            cid: Content Identifier (CID) of the object to restore
        
        Returns:
            Response indicating successful restoration
        """
        return await self._make_request("POST", f"/api/objects/{cid}/restore")

    async def download_object(self, cid: str) -> bytes:
        """
        GET /api/downloads/{cid} - Download an object by CID (direct download, loads entire file into memory).
        
        Note: The download endpoint uses https://public.auto-drive.autonomys.xyz as base URL
        and requires Accept: application/octet-stream header.
        
        Note: The download endpoint may not be immediately available after upload.
        The file may need time to be processed. If download fails, the upload was still successful.
        
        For large files, use download_object_stream() instead.
        
        Args:
            cid: Content Identifier (CID) of the object
        
        Returns:
            File content as bytes
        """
        # Download endpoint uses different base URL and headers
        download_base_url = "https://public.auto-drive.autonomys.xyz"
        endpoint = f"/api/downloads/{cid}"
        full_url = f"{download_base_url}{endpoint}"
        
        # Use different headers for download (Accept: application/octet-stream)
        download_headers = {
            'Authorization': f"Bearer {self.api_key}",
            'X-Auth-Provider': self.auth_provider,
            'Accept': 'application/octet-stream'
        }
        
        try:
            # Create a temporary client for download with correct base URL and headers
            async with httpx.AsyncClient(
                base_url=download_base_url,
                headers=download_headers,
                timeout=120.0
            ) as download_client:
                response = await download_client.get(endpoint)
            
            if response.status_code == 200:
                self._log_request("GET", full_url, response.status_code, f"<binary content: {len(response.content)} bytes>", None)
                return response.content
            else:
                error_data = None
                try:
                    error_data = response.json()
                except:
                    error_data = response.text
                
                self._log_request("GET", full_url, response.status_code, error_data, None)
                
                message = error_data.get('error', error_data.get('message', response.text)) if isinstance(error_data, dict) else str(error_data)
                error_msg = f"{response.reason_phrase}: {message}"
                if error_data:
                    error_msg += f" | Details: {error_data}"
                
                raise AutoDriveAPIError(
                    error_msg,
                    status_code=response.status_code,
                    response_body=error_data
                )
        except httpx.HTTPError as e:
            self._log_request("GET", full_url, None, None, None)
            raise AutoDriveAPIError(f"Network Error: {str(e)}")
        except AutoDriveAPIError:
            raise
        except Exception as e:
            self._log_request("GET", full_url, None, None, None)
            raise AutoDriveAPIError(f"Request Error: {str(e)}")

    async def download_object_stream(self, cid: str) -> bytes:
        """
        GET /api/downloads/{cid} - Download an object by CID using streaming (for large files).
        Uses streaming to avoid loading entire file into memory.
        
        Note: The download endpoint uses https://public.auto-drive.autonomys.xyz as base URL
        and requires Accept: application/octet-stream header.
        
        Args:
            cid: Content Identifier (CID) of the object
        
        Returns:
            File content as bytes
        """
        # Download endpoint uses different base URL and headers
        download_base_url = "https://public.auto-drive.autonomys.xyz"
        endpoint = f"/api/downloads/{cid}"
        full_url = f"{download_base_url}{endpoint}"
        
        # Use different headers for download (Accept: application/octet-stream)
        download_headers = {
            'Authorization': f"Bearer {self.api_key}",
            'X-Auth-Provider': self.auth_provider,
            'Accept': 'application/octet-stream'
        }
        
        try:
            # Create a temporary client for download with correct base URL and headers
            async with httpx.AsyncClient(
                base_url=download_base_url,
                headers=download_headers,
                timeout=120.0
            ) as download_client:
                async with download_client.stream("GET", endpoint) as response:
                    if response.status_code == 200:
                        content = b""
                        async for chunk in response.aiter_bytes():
                            content += chunk
                        self._log_request("GET", full_url, response.status_code, f"<binary content: {len(content)} bytes>", None)
                        return content
                    else:
                        # Read error response
                        error_data = None
                        try:
                            error_content = b""
                            async for chunk in response.aiter_bytes():
                                error_content += chunk
                            if error_content:
                                try:
                                    error_data = json.loads(error_content.decode('utf-8'))
                                except:
                                    error_data = error_content.decode('utf-8', errors='ignore')
                        except Exception as e:
                            error_data = str(e)
                        
                        self._log_request("GET", full_url, response.status_code, error_data, None)
                        
                        message = error_data.get('error', error_data.get('message', str(error_data))) if isinstance(error_data, dict) else str(error_data)
                        error_msg = f"{response.reason_phrase}: {message}"
                        if error_data:
                            error_msg += f" | Details: {error_data}"
                        
                        raise AutoDriveAPIError(
                            error_msg,
                            status_code=response.status_code,
                            response_body=error_data
                        )
        except httpx.HTTPError as e:
            self._log_request("GET", full_url, None, None, None)
            raise AutoDriveAPIError(f"Network Error: {str(e)}")
        except AutoDriveAPIError:
            raise
        except Exception as e:
            self._log_request("GET", full_url, None, None, None)
            raise AutoDriveAPIError(f"Stream download failed: {str(e)}")

    async def download_public_object(self, object_id: str) -> bytes:
        """
        GET /api/objects/{id}/public - Download a public object by id (direct download, loads entire file into memory).
        
        This endpoint uses the object's ID (not CID) to download objects that have been published and made public.
        Public objects may be accessible with different permissions than regular objects.
        
        Args:
            object_id: Object ID (not CID) of the public object
        
        Returns:
            File content as bytes
        """
        path = f"/api/objects/{object_id}/public"
        
        try:
            response = await self.client.get(path)
            
            response_data = None
            try:
                if response.status_code != 200:
                    response_data = response.json()
            except:
                response_data = response.text
            
            self._log_request("GET", f"{self.base_url}{path}", response.status_code, response_data, None)
            
            if response.status_code == 200:
                return response.content
            else:
                error_data = response_data
                message = error_data.get('error', error_data.get('message', response.text)) if isinstance(error_data, dict) else str(error_data)
                
                error_msg = f"{response.reason_phrase}: {message}"
                if error_data:
                    error_msg += f" | Details: {error_data}"
                    
                raise AutoDriveAPIError(
                    error_msg,
                    status_code=response.status_code,
                    response_body=error_data
                )
        except httpx.HTTPError as e:
            self._log_request("GET", f"{self.base_url}{path}", None, None, None)
            raise AutoDriveAPIError(f"Network Error: {str(e)}")
        except AutoDriveAPIError:
            raise
        except Exception as e:
            self._log_request("GET", f"{self.base_url}{path}", None, None, None)
            raise AutoDriveAPIError(f"Request Error: {str(e)}")

    async def download_public_object_stream(self, object_id: str) -> bytes:
        """
        GET /api/objects/{id}/public - Download a public object by id using streaming (for large files).
        Uses streaming to avoid loading entire file into memory.
        
        This endpoint uses the object's ID (not CID) to download objects that have been published and made public.
        
        Args:
            object_id: Object ID (not CID) of the public object
        
        Returns:
            File content as bytes
        """
        path = f"/api/objects/{object_id}/public"
        
        try:
            async with self.client.stream("GET", path) as response:
                if response.status_code == 200:
                    content = b""
                    async for chunk in response.aiter_bytes():
                        content += chunk
                    return content
                else:
                    # Read error response
                    error_data = None
                    try:
                        error_content = b""
                        async for chunk in response.aiter_bytes():
                            error_content += chunk
                        if error_content:
                            try:
                                error_data = json.loads(error_content.decode('utf-8'))
                            except:
                                error_data = error_content.decode('utf-8', errors='ignore')
                    except Exception as e:
                        error_data = str(e)
                    
                    message = error_data.get('error', error_data.get('message', str(error_data))) if isinstance(error_data, dict) else str(error_data)
                    error_msg = f"{response.reason_phrase}: {message}"
                    if error_data:
                        error_msg += f" | Details: {error_data}"
                    
                    raise AutoDriveAPIError(
                        error_msg,
                        status_code=response.status_code,
                        response_body=error_data
                    )
        except httpx.HTTPError as e:
            raise AutoDriveAPIError(f"Network Error during stream download: {str(e)}")
        except AutoDriveAPIError:
            raise
        except Exception as e:
            raise AutoDriveAPIError(f"Stream download failed: {str(e)}")

    # --- Async Download Methods ---

    async def create_async_download(self, cid: str) -> Dict[str, Any]:
        """
        POST /api/downloads/async/{cid} - Create async download for an object by CID
        
        Note: This endpoint uses https://public.auto-drive.autonomys.xyz as base URL
        and requires Accept: application/json header.
        
        Args:
            cid: Content Identifier (CID) of the object to download
        
        Returns:
            Download information including download_id
        """
        # Async download endpoint uses different base URL (public domain)
        download_base_url = "https://public.auto-drive.autonomys.xyz"
        endpoint = f"/api/downloads/async/{cid}"
        full_url = f"{download_base_url}{endpoint}"
        
        # Use different headers for async download (Accept: application/json)
        download_headers = {
            'Authorization': f"Bearer {self.api_key}",
            'X-Auth-Provider': self.auth_provider,
            'Accept': 'application/json'
        }
        
        try:
            # Create a temporary client for async download with correct base URL and headers
            async with httpx.AsyncClient(
                base_url=download_base_url,
                headers=download_headers,
                timeout=120.0
            ) as download_client:
                response = await download_client.post(endpoint)
            
            response_data = None
            try:
                if response.status_code != 204:
                    response_data = response.json()
            except:
                response_data = response.text
            
            self._log_request("POST", full_url, response.status_code, response_data, None)
            
            if response.status_code >= 400:
                error_data = response_data
                message = error_data.get('error', error_data.get('message', response.text)) if isinstance(error_data, dict) else str(error_data)
                
                error_msg = f"{response.reason_phrase}: {message}"
                if error_data:
                    error_msg += f" | Details: {error_data}"
                    
                raise AutoDriveAPIError(
                    error_msg,
                    status_code=response.status_code,
                    response_body=error_data
                )
            
            if response.status_code == 204:
                return None
                
            return response_data
        except httpx.HTTPError as e:
            self._log_request("POST", full_url, None, None, None)
            raise AutoDriveAPIError(f"Network Error: {str(e)}")
        except AutoDriveAPIError:
            raise
        except Exception as e:
            self._log_request("POST", full_url, None, None, None)
            raise AutoDriveAPIError(f"Request Error: {str(e)}")

    async def get_async_download_status(self, download_id: str) -> Dict[str, Any]:
        """
        GET /api/downloads/async/{download_id}/status - Get async download status
        
        Note: This endpoint uses https://public.auto-drive.autonomys.xyz as base URL.
        
        Args:
            download_id: The download task ID
        
        Returns:
            Download status including fileSize, downloaded, createdAt, updatedAt
        """
        # Async download endpoint uses different base URL (public domain)
        download_base_url = "https://public.auto-drive.autonomys.xyz"
        endpoint = f"/api/downloads/async/{download_id}/status"
        full_url = f"{download_base_url}{endpoint}"
        
        download_headers = {
            'Authorization': f"Bearer {self.api_key}",
            'X-Auth-Provider': self.auth_provider,
            'Accept': 'application/json'
        }
        
        try:
            async with httpx.AsyncClient(
                base_url=download_base_url,
                headers=download_headers,
                timeout=120.0
            ) as download_client:
                response = await download_client.get(endpoint)
            
            response_data = None
            try:
                if response.status_code != 204:
                    response_data = response.json()
            except:
                response_data = response.text
            
            self._log_request("GET", full_url, response.status_code, response_data, None)
            
            if response.status_code >= 400:
                error_data = response_data
                message = error_data.get('error', error_data.get('message', response.text)) if isinstance(error_data, dict) else str(error_data)
                error_msg = f"{response.reason_phrase}: {message}"
                if error_data:
                    error_msg += f" | Details: {error_data}"
                raise AutoDriveAPIError(error_msg, status_code=response.status_code, response_body=error_data)
            
            if response.status_code == 204:
                return None
            return response_data
        except httpx.HTTPError as e:
            self._log_request("GET", full_url, None, None, None)
            raise AutoDriveAPIError(f"Network Error: {str(e)}")
        except AutoDriveAPIError:
            raise
        except Exception as e:
            self._log_request("GET", full_url, None, None, None)
            raise AutoDriveAPIError(f"Request Error: {str(e)}")

    async def list_async_downloads(self, download_id: Optional[str] = None) -> Dict[str, Any]:
        """
        GET /api/downloads/async/{downloadId} - Get async download information by download ID
        
        Note: This endpoint uses https://public.auto-drive.autonomys.xyz as base URL.
        
        Args:
            download_id: Optional download task ID. If provided, returns information for that specific download.
                        If not provided, this method may not work as the API requires a download ID.
        
        Returns:
            Download task information
        """
        if not download_id:
            raise ValueError("download_id is required for GET /api/downloads/async/{downloadId}")
        
        endpoint = f"/api/downloads/async/{download_id}"
        
        # Async download endpoint uses different base URL (public domain)
        download_base_url = "https://public.auto-drive.autonomys.xyz"
        full_url = f"{download_base_url}{endpoint}"
        
        download_headers = {
            'Authorization': f"Bearer {self.api_key}",
            'X-Auth-Provider': self.auth_provider,
            'Accept': 'application/json'
        }
        
        try:
            async with httpx.AsyncClient(
                base_url=download_base_url,
                headers=download_headers,
                timeout=120.0
            ) as download_client:
                response = await download_client.get(endpoint)
            
            response_data = None
            try:
                if response.status_code != 204:
                    response_data = response.json()
            except:
                response_data = response.text
            
            self._log_request("GET", full_url, response.status_code, response_data, None)
            
            if response.status_code >= 400:
                error_data = response_data
                message = error_data.get('error', error_data.get('message', response.text)) if isinstance(error_data, dict) else str(error_data)
                error_msg = f"{response.reason_phrase}: {message}"
                if error_data:
                    error_msg += f" | Details: {error_data}"
                raise AutoDriveAPIError(error_msg, status_code=response.status_code, response_body=error_data)
            
            if response.status_code == 204:
                return None
            return response_data
        except httpx.HTTPError as e:
            self._log_request("GET", full_url, None, None, None)
            raise AutoDriveAPIError(f"Network Error: {str(e)}")
        except AutoDriveAPIError:
            raise
        except Exception as e:
            self._log_request("GET", full_url, None, None, None)
            raise AutoDriveAPIError(f"Request Error: {str(e)}")

    async def dismiss_async_download(self, download_id: str) -> None:
        """
        POST /api/downloads/async/{download_id}/dismiss - Dismiss an async download
        
        Note: This endpoint uses https://public.auto-drive.autonomys.xyz as base URL.
        
        Args:
            download_id: The download task ID to dismiss
        """
        # Async download endpoint uses different base URL (public domain)
        download_base_url = "https://public.auto-drive.autonomys.xyz"
        endpoint = f"/api/downloads/async/{download_id}/dismiss"
        full_url = f"{download_base_url}{endpoint}"
        
        download_headers = {
            'Authorization': f"Bearer {self.api_key}",
            'X-Auth-Provider': self.auth_provider,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        try:
            async with httpx.AsyncClient(
                base_url=download_base_url,
                headers=download_headers,
                timeout=120.0
            ) as download_client:
                response = await download_client.post(endpoint)
            
            response_data = None
            try:
                if response.status_code != 204:
                    response_data = response.json()
            except:
                response_data = response.text
            
            self._log_request("POST", full_url, response.status_code, response_data, None)
            
            if response.status_code >= 400:
                error_data = response_data
                message = error_data.get('error', error_data.get('message', response.text)) if isinstance(error_data, dict) else str(error_data)
                error_msg = f"{response.reason_phrase}: {message}"
                if error_data:
                    error_msg += f" | Details: {error_data}"
                raise AutoDriveAPIError(error_msg, status_code=response.status_code, response_body=error_data)
        except httpx.HTTPError as e:
            self._log_request("POST", full_url, None, None, None)
            raise AutoDriveAPIError(f"Network Error: {str(e)}")
        except AutoDriveAPIError:
            raise
        except Exception as e:
            self._log_request("POST", full_url, None, None, None)
            raise AutoDriveAPIError(f"Request Error: {str(e)}")

    async def close(self):
        """Alias for aclose() for backward compatibility"""
        await self.aclose()
