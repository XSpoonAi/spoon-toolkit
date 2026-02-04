"""Download-related tools for Autonomys Auto Drive"""

import os
from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider
from .provider import AutoDriveAPIError

class DownloadObjectTool(BaseTool):
    name: str = "download_object"
    description: str = "Download a file from Autonomys Auto Drive by its CID. Downloads the entire file and saves it. If destination_path is not provided, saves to current working directory with CID as filename. If destination_path is a directory, saves to that directory with CID as filename. Recommended for smaller files. For large files, use download_object_stream instead."
    parameters: dict = {
        "type": "object",
        "properties": {
            "cid": {
                "type": "string",
                "description": "The Content Identifier (CID) of the object to download"
            },
            "destination_path": {
                "type": "string",
                "description": "Optional path where the file should be saved. If not provided, saves to current working directory with CID as filename. If a directory is provided, the CID will be used as the filename. If a full file path is provided, uses that path."
            }
        },
        "required": ["cid"]
    }

    async def execute(self, cid: str, destination_path: str = None) -> ToolResult:
        try:
            # Download file content (provider returns bytes)
            async with get_provider() as provider:
                content = await provider.download_object(cid)
            
            file_size = len(content)
            
            # Determine save path
            if destination_path is None:
                # Default: save to current working directory with CID as filename
                destination_path = os.path.join(os.getcwd(), cid)
            elif os.path.isdir(destination_path):
                # If directory provided, use CID as filename
                destination_path = os.path.join(destination_path, cid)
            # else: use provided path as-is
            
            # Save to file
            with open(destination_path, 'wb') as f:
                f.write(content)
            
            return ToolResult(output=f"File downloaded and saved to {destination_path} ({file_size} bytes)")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Download failed: {str(e)}")

class StreamDownloadTool(BaseTool):
    name: str = "download_object_stream"
    description: str = "Download a file from Autonomys Auto Drive using streaming (GET /api/downloads/{cid}), which is safer for large files. Uses streaming to avoid loading entire file into memory. If destination_path is not provided, saves to current working directory with CID as filename. If destination_path is a directory, saves to that directory with CID as filename."
    parameters: dict = {
        "type": "object",
        "properties": {
            "cid": {
                "type": "string",
                "description": "The Content Identifier (CID) of the object to download"
            },
            "destination_path": {
                "type": "string",
                "description": "Optional path where the file should be saved. If not provided, saves to current working directory with CID as filename. If a directory is provided, the CID will be used as the filename. If a full file path is provided, uses that path."
            }
        },
        "required": ["cid"]
    }

    async def execute(self, cid: str, destination_path: str = None) -> ToolResult:
        try:
            # Download file content (provider returns bytes)
            async with get_provider() as provider:
                content = await provider.download_object_stream(cid)
            
            file_size = len(content)
            
            # Determine save path
            if destination_path is None:
                # Default: save to current working directory with CID as filename
                destination_path = os.path.join(os.getcwd(), cid)
            elif os.path.isdir(destination_path):
                # If directory provided, use CID as filename
                destination_path = os.path.join(destination_path, cid)
            # else: use provided path as-is
            
            # Save to file
            with open(destination_path, 'wb') as f:
                f.write(content)
            
            return ToolResult(output=f"Streaming download for CID {cid} completed and saved to {destination_path} ({file_size} bytes)")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Streaming download failed: {str(e)}")

class DownloadPublicObjectTool(BaseTool):
    name: str = "download_public_object"
    description: str = "Download a public object from Autonomys Auto Drive by its object ID (not CID) using GET /api/objects/{id}/public. Downloads the entire file and saves it. If destination_path is not provided, saves to current working directory with object_id as filename. If destination_path is a directory, saves to that directory with object_id as filename. Recommended for smaller files."
    parameters: dict = {
        "type": "object",
        "properties": {
            "object_id": {
                "type": "string",
                "description": "The object ID (not CID) of the public object to download"
            },
            "destination_path": {
                "type": "string",
                "description": "Optional path where the file should be saved. If not provided, saves to current working directory with object_id as filename. If a directory is provided, the object_id will be used as the filename. If a full file path is provided, uses that path."
            }
        },
        "required": ["object_id"]
    }

    async def execute(self, object_id: str, destination_path: str = None) -> ToolResult:
        try:
            # Download file content (provider returns bytes)
            async with get_provider() as provider:
                content = await provider.download_public_object(object_id)
            
            file_size = len(content)
            
            # Determine save path
            if destination_path is None:
                # Default: save to current working directory with object_id as filename
                destination_path = os.path.join(os.getcwd(), object_id)
            elif os.path.isdir(destination_path):
                # If directory provided, use object_id as filename
                destination_path = os.path.join(destination_path, object_id)
            # else: use provided path as-is
            
            # Save to file
            with open(destination_path, 'wb') as f:
                f.write(content)
            
            return ToolResult(output=f"Public object downloaded and saved to {destination_path} ({file_size} bytes)")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Download failed: {str(e)}")

class StreamDownloadPublicObjectTool(BaseTool):
    name: str = "download_public_object_stream"
    description: str = "Download a public object from Autonomys Auto Drive by its object ID (not CID) using streaming (GET /api/objects/{id}/public), which is safer for large files. Uses streaming to avoid loading entire file into memory. If destination_path is not provided, saves to current working directory with object_id as filename. If destination_path is a directory, saves to that directory with object_id as filename."
    parameters: dict = {
        "type": "object",
        "properties": {
            "object_id": {
                "type": "string",
                "description": "The object ID (not CID) of the public object to download"
            },
            "destination_path": {
                "type": "string",
                "description": "Optional path where the file should be saved. If not provided, saves to current working directory with object_id as filename. If a directory is provided, the object_id will be used as the filename. If a full file path is provided, uses that path."
            }
        },
        "required": ["object_id"]
    }

    async def execute(self, object_id: str, destination_path: str = None) -> ToolResult:
        try:
            # Download file content (provider returns bytes)
            async with get_provider() as provider:
                content = await provider.download_public_object_stream(object_id)
            
            file_size = len(content)
            
            # Determine save path
            if destination_path is None:
                # Default: save to current working directory with object_id as filename
                destination_path = os.path.join(os.getcwd(), object_id)
            elif os.path.isdir(destination_path):
                # If directory provided, use object_id as filename
                destination_path = os.path.join(destination_path, object_id)
            # else: use provided path as-is
            
            # Save to file
            with open(destination_path, 'wb') as f:
                f.write(content)
            
            return ToolResult(output=f"Streaming download for public object {object_id} completed and saved to {destination_path} ({file_size} bytes)")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Streaming download failed: {str(e)}")

class CreateAsyncDownloadTool(BaseTool):
    name: str = "create_async_download"
    description: str = "Create an asynchronous download task for an object by CID on Autonomys Auto Drive. This initiates a background download process."
    parameters: dict = {
        "type": "object",
        "properties": {
            "cid": {
                "type": "string",
                "description": "The Content Identifier (CID) of the object to download"
            }
        },
        "required": ["cid"]
    }

    async def execute(self, cid: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.create_async_download(cid)
                download_id = result.get('id') or result.get('downloadId')
                return ToolResult(output=f"Async download created successfully. Download ID: {download_id}, Result: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to create async download: {str(e)}")

class GetAsyncDownloadStatusTool(BaseTool):
    name: str = "get_async_download_status"
    description: str = "Get the status of an asynchronous download task by download ID on Autonomys Auto Drive."
    parameters: dict = {
        "type": "object",
        "properties": {
            "download_id": {
                "type": "string",
                "description": "The download task ID"
            }
        },
        "required": ["download_id"]
    }

    async def execute(self, download_id: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.get_async_download_status(download_id)
                return ToolResult(output=f"Async download status: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to get async download status: {str(e)}")

class ListAsyncDownloadsTool(BaseTool):
    name: str = "list_async_downloads"
    description: str = "Get asynchronous download task information by download ID on Autonomys Auto Drive using GET /api/downloads/async/{downloadId}."
    parameters: dict = {
        "type": "object",
        "properties": {
            "download_id": {
                "type": "string",
                "description": "The download task ID to retrieve information for"
            }
        },
        "required": ["download_id"]
    }

    async def execute(self, download_id: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.list_async_downloads(download_id=download_id)
                return ToolResult(output=f"Async download info: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to get async download info: {str(e)}")

class DismissAsyncDownloadTool(BaseTool):
    name: str = "dismiss_async_download"
    description: str = "Dismiss an asynchronous download task by download ID on Autonomys Auto Drive."
    parameters: dict = {
        "type": "object",
        "properties": {
            "download_id": {
                "type": "string",
                "description": "The download task ID to dismiss"
            }
        },
        "required": ["download_id"]
    }

    async def execute(self, download_id: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                await provider.dismiss_async_download(download_id)
                return ToolResult(output=f"Async download {download_id} dismissed successfully")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to dismiss async download: {str(e)}")
