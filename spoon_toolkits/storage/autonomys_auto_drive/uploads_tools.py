"""Upload-related tools for Autonomys Auto Drive"""

import os
import logging
from typing import Any
from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider
from .mime_type import suffix_to_mime_type_dict
from .provider import AutoDriveAPIError

# Configuration from environment or defaults
DEFAULT_CHUNK_SIZE = int(os.environ.get("AUTODRIVE_CHUNK_SIZE", 5 * 1024 * 1024))
# Threshold to switch from direct upload to multipart (e.g., 25MB)
DIRECT_UPLOAD_THRESHOLD = int(os.environ.get("AUTODRIVE_DIRECT_THRESHOLD", 25 * 1024 * 1024))

logger = logging.getLogger(__name__)

async def _upload_file_internal(
    provider: Any, 
    file_path: str, 
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    threshold: int = DIRECT_UPLOAD_THRESHOLD
) -> Any:
    """
    Internal helper to upload a file, automatically choosing between simple and multipart upload.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found at {file_path}")

    file_size = os.path.getsize(file_path)
    filename = os.path.basename(file_path)
    _, suffix = os.path.splitext(file_path)
    mime_type = suffix_to_mime_type_dict.get(suffix, 'application/octet-stream')

    # If file is small, use direct upload
    if file_size <= threshold:
        return await provider.upload_file_small(file_path, filename, mime_type)
    
    # For large files, use multipart upload
    return await provider.upload_file_large(file_path, chunk_size=chunk_size)

class UploadFileTool(BaseTool):
    name: str = "upload_file"
    description: str = "Upload a file to Autonomys Auto Drive. Automatically handles large files via multipart upload."
    parameters: dict = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Full path to the local file to upload"
            }
        },
        "required": ["file_path"]
    }

    async def execute(self, file_path: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await _upload_file_internal(provider, file_path)
                return ToolResult(output=f"File uploaded successfully: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Upload failed: {str(e)}")

class UploadFileSmallTool(BaseTool):
    name: str = "upload_file_small"
    description: str = "Upload a small file directly to Autonomys Auto Drive. Use this for files that can be uploaded in a single request."
    parameters: dict = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Full path to the local file to upload"
            },
            "filename": {
                "type": "string",
                "description": "Name of the file (optional, defaults to basename of file_path)"
            },
            "mime_type": {
                "type": "string",
                "description": "MIME type of the file (optional, will be auto-detected from extension if not provided)",
                "default": "application/octet-stream"
            }
        },
        "required": ["file_path"]
    }

    async def execute(self, file_path: str, filename: str = None, mime_type: str = None) -> ToolResult:
        try:
            if not os.path.isfile(file_path):
                return ToolResult(error=f"File not found: {file_path}")
            
            if filename is None:
                filename = os.path.basename(file_path)
            
            if mime_type is None:
                _, suffix = os.path.splitext(file_path)
                mime_type = suffix_to_mime_type_dict.get(suffix, 'application/octet-stream')
            
            async with get_provider() as provider:
                result = await provider.upload_file_small(file_path, filename, mime_type)
                cid = result.get('cid') or result.get('id') or result.get('contentId')
                return ToolResult(output=f"Small file uploaded successfully. CID: {cid}, Result: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Upload failed: {str(e)}")

class UploadFileLargeTool(BaseTool):
    name: str = "upload_file_large"
    description: str = "Upload a large file to Autonomys Auto Drive using chunked upload. Use this for files that need to be split into multiple parts."
    parameters: dict = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Full path to the local file to upload"
            },
            "chunk_size": {
                "type": "integer",
                "description": "Size of each chunk in bytes (default: 5MB)",
                "default": 5242880
            },
            "concurrency": {
                "type": "integer",
                "description": "Number of concurrent chunk uploads (default: 1, API requires sequential upload)",
                "default": 1
            },
            "retry": {
                "type": "integer",
                "description": "Number of retry attempts for failed chunks (default: 3)",
                "default": 3
            },
            "resume": {
                "type": "boolean",
                "description": "Whether to resume interrupted uploads (default: true)",
                "default": True
            }
        },
        "required": ["file_path"]
    }

    async def execute(self, file_path: str, chunk_size: int = 5242880, concurrency: int = 1, retry: int = 3, resume: bool = True) -> ToolResult:
        try:
            if not os.path.isfile(file_path):
                return ToolResult(error=f"File not found: {file_path}")
            
            async with get_provider() as provider:
                result = await provider.upload_file_large(file_path, chunk_size=chunk_size, concurrency=concurrency, retry=retry, resume=resume)
                cid = result.get('cid') or result.get('id') or result.get('contentId')
                return ToolResult(output=f"Large file uploaded successfully. CID: {cid}, Result: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Upload failed: {str(e)}")

class GetUploadStatusTool(BaseTool):
    name: str = "get_upload_status"
    description: str = "Get the status of an upload session by upload ID. Useful for resuming interrupted uploads."
    parameters: dict = {
        "type": "object",
        "properties": {
            "upload_id": {
                "type": "string",
                "description": "The upload session ID"
            }
        },
        "required": ["upload_id"]
    }

    async def execute(self, upload_id: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.get_upload_status(upload_id)
                return ToolResult(output=f"Upload status: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to get upload status: {str(e)}")

