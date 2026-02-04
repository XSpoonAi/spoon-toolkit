"""Upload-related tools for Autonomys Auto Drive"""

import os
import logging
from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider
from .mime_type import suffix_to_mime_type_dict
from .provider import AutoDriveAPIError

# Configuration from environment or defaults
DEFAULT_CHUNK_SIZE = int(os.environ.get("AUTODRIVE_CHUNK_SIZE", 5 * 1024 * 1024))
# Threshold to switch from direct upload to chunked upload (default: 25MB)
DIRECT_UPLOAD_THRESHOLD = int(os.environ.get("AUTODRIVE_DIRECT_THRESHOLD", 25 * 1024 * 1024))

logger = logging.getLogger(__name__)


class UploadFileTool(BaseTool):
    """
    Smart upload tool that automatically chooses between small file upload and large file chunked upload.
    
    This is the recommended tool for most use cases. It automatically:
    - Uses direct upload for files <= 25MB
    - Uses chunked upload for files > 25MB
    
    For advanced control, use UploadFileSmallTool or UploadFileLargeTool directly.
    """
    name: str = "upload_file"
    description: str = "Upload a file to Autonomys Auto Drive. Automatically chooses the best upload method based on file size."
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
        """
        Execute file upload with automatic method selection.
        """
        try:
            if not os.path.isfile(file_path):
                return ToolResult(error=f"File not found: {file_path}")
            
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            _, suffix = os.path.splitext(file_path)
            mime_type = suffix_to_mime_type_dict.get(suffix, 'application/octet-stream')
            
            async with get_provider() as provider:
                # Automatically choose upload method based on file size
                if file_size <= DIRECT_UPLOAD_THRESHOLD:
                    # Small file: use direct upload
                    result = await provider.upload_file_small(file_path, filename, mime_type)
                    upload_method = "direct"
                else:
                    # Large file: use chunked upload
                    result = await provider.upload_file_large(file_path, chunk_size=DEFAULT_CHUNK_SIZE, mime_type=mime_type)
                    upload_method = "chunked"
                
                cid = result.get('cid') or result.get('id') or result.get('contentId')
                return ToolResult(
                    output=f"File uploaded successfully using {upload_method} upload. CID: {cid}, Size: {file_size} bytes"
                )
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Upload failed: {str(e)}")

class UploadFileSmallTool(BaseTool):
    """
    Tool for uploading small files directly (single request).
    
    Use this when:
    - You know the file is small and want direct upload
    - You need to customize filename or mime_type
    - You want to bypass automatic method selection
    
    For automatic method selection, use UploadFileTool instead.
    """
    name: str = "upload_file_small"
    description: str = "Upload a small file directly to Autonomys Auto Drive in a single request. Use this when you need precise control over small file uploads."
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
    """
    Tool for uploading large files using chunked upload.
    
    Use this when:
    - You know the file is large and want chunked upload
    - You need to customize chunk_size, retry, resume, or mime_type
    - You want to bypass automatic method selection
    
    For automatic method selection, use UploadFileTool instead.
    """
    name: str = "upload_file_large"
    description: str = "Upload a large file to Autonomys Auto Drive using chunked upload. Use this when you need precise control over large file uploads with custom chunking parameters."
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
            },
            "mime_type": {
                "type": "string",
                "description": "MIME type of the file (optional, will be auto-detected from extension if not provided)",
                "default": "application/octet-stream"
            }
        },
        "required": ["file_path"]
    }

    async def execute(self, file_path: str, chunk_size: int = 5242880, concurrency: int = 1, retry: int = 3, resume: bool = True, mime_type: str = None) -> ToolResult:
        try:
            if not os.path.isfile(file_path):
                return ToolResult(error=f"File not found: {file_path}")
            
            async with get_provider() as provider:
                result = await provider.upload_file_large(
                    file_path, 
                    chunk_size=chunk_size, 
                    concurrency=concurrency, 
                    retry=retry, 
                    resume=resume,
                    mime_type=mime_type
                )
                cid = result.get('cid') or result.get('id') or result.get('contentId')
                return ToolResult(output=f"Large file uploaded successfully. CID: {cid}, Result: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Upload failed: {str(e)}")

class GetUploadStatusTool(BaseTool):
    """
    Tool for getting the status of an upload session.
    
    Useful for:
    - Checking upload progress
    - Resuming interrupted uploads
    - Debugging upload issues
    """
    name: str = "get_upload_status"
    description: str = "Get the status of an upload session by upload ID. Useful for checking progress and resuming interrupted uploads."
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

