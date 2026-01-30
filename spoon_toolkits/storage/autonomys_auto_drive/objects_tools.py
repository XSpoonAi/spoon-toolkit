"""Object-related tools for Autonomys Auto Drive"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider
from .provider import AutoDriveAPIError

class GetRootObjectsTool(BaseTool):
    name: str = "get_root_objects"
    description: str = "Get root objects from Autonomys Auto Drive. Lists objects uploaded by the user or globally based on scope parameter."
    parameters: dict = {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of objects to return",
                "default": 10
            },
            "offset": {
                "type": "integer",
                "description": "Number of objects to skip",
                "default": 0
            },
            "scope": {
                "type": "string",
                "description": "Scope of objects to retrieve - 'global' or 'user'",
                "enum": ["global", "user"],
                "default": "user"
            }
        },
        "required": []
    }

    async def execute(self, limit: int = 10, offset: int = 0, scope: str = "user") -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.get_root_objects(limit, offset, scope)
                return ToolResult(output=f"Objects: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to get root objects: {str(e)}")

class SearchObjectsTool(BaseTool):
    name: str = "search_objects"
    description: str = "Search for objects on Autonomys Auto Drive by name or CID."
    parameters: dict = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search query (name or CID)"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of results to return",
                "default": 10
            },
            "scope": {
                "type": "string",
                "description": "Scope of the search - 'global' or 'user'",
                "enum": ["global", "user"],
                "default": "user"
            }
        },
        "required": ["query"]
    }

    async def execute(self, query: str, limit: int = 10, scope: str = "user") -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.search_objects(query, limit, scope)
                return ToolResult(output=f"Search results: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Search failed: {str(e)}")

class PublishObjectTool(BaseTool):
    name: str = "publish_object"
    description: str = "Publish an object by CID on Autonomys Auto Drive. This makes the object publicly accessible and returns an object ID."
    parameters: dict = {
        "type": "object",
        "properties": {
            "cid": {
                "type": "string",
                "description": "The Content Identifier (CID) of the object to publish"
            }
        },
        "required": ["cid"]
    }

    async def execute(self, cid: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.publish_object(cid)
                object_id = result.get('result') if isinstance(result, dict) else result
                return ToolResult(output=f"Object published successfully. Object ID: {object_id}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to publish object: {str(e)}")

class UnpublishObjectTool(BaseTool):
    name: str = "unpublish_object"
    description: str = "Unpublish an object by CID on Autonomys Auto Drive. This removes the object from public access."
    parameters: dict = {
        "type": "object",
        "properties": {
            "cid": {
                "type": "string",
                "description": "The Content Identifier (CID) of the object to unpublish"
            }
        },
        "required": ["cid"]
    }

    async def execute(self, cid: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                await provider.unpublish_object(cid)
                return ToolResult(output=f"Object unpublished successfully")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to unpublish object: {str(e)}")

class DeleteObjectTool(BaseTool):
    name: str = "delete_object"
    description: str = "Delete an object by CID on Autonomys Auto Drive."
    parameters: dict = {
        "type": "object",
        "properties": {
            "cid": {
                "type": "string",
                "description": "The Content Identifier (CID) of the object to delete"
            }
        },
        "required": ["cid"]
    }

    async def execute(self, cid: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                await provider.delete_object(cid)
                return ToolResult(output=f"Object deleted successfully")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to delete object: {str(e)}")

class RestoreObjectTool(BaseTool):
    name: str = "restore_object"
    description: str = "Restore a deleted object by CID on Autonomys Auto Drive."
    parameters: dict = {
        "type": "object",
        "properties": {
            "cid": {
                "type": "string",
                "description": "The Content Identifier (CID) of the object to restore"
            }
        },
        "required": ["cid"]
    }

    async def execute(self, cid: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                await provider.restore_object(cid)
                return ToolResult(output=f"Object restored successfully")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to restore object: {str(e)}")

class GetSharedRootObjectsTool(BaseTool):
    name: str = "get_shared_root_objects"
    description: str = "Get shared root objects from Autonomys Auto Drive. These are objects that have been shared with you by other users."
    parameters: dict = {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of objects to return",
                "default": 10
            },
            "offset": {
                "type": "integer",
                "description": "Number of objects to skip",
                "default": 0
            }
        },
        "required": []
    }

    async def execute(self, limit: int = 10, offset: int = 0) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.get_shared_root_objects(limit, offset)
                return ToolResult(output=f"Shared objects: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to get shared root objects: {str(e)}")

class GetDeletedRootObjectsTool(BaseTool):
    name: str = "get_deleted_root_objects"
    description: str = "Get deleted root objects from Autonomys Auto Drive. These are objects that have been deleted but can potentially be restored."
    parameters: dict = {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of objects to return",
                "default": 10
            },
            "offset": {
                "type": "integer",
                "description": "Number of objects to skip",
                "default": 0
            }
        },
        "required": []
    }

    async def execute(self, limit: int = 10, offset: int = 0) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.get_deleted_root_objects(limit, offset)
                return ToolResult(output=f"Deleted objects: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to get deleted root objects: {str(e)}")

class GetObjectSummaryTool(BaseTool):
    name: str = "get_object_summary"
    description: str = "Get a summary of an object by CID on Autonomys Auto Drive. This provides a concise overview of the object."
    parameters: dict = {
        "type": "object",
        "properties": {
            "cid": {
                "type": "string",
                "description": "The Content Identifier (CID) of the object"
            }
        },
        "required": ["cid"]
    }

    async def execute(self, cid: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.get_object_summary(cid)
                return ToolResult(output=f"Object summary: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to get object summary: {str(e)}")

class ShareObjectTool(BaseTool):
    name: str = "share_object"
    description: str = "Share an object by CID on Autonomys Auto Drive. This makes the object accessible to others using the provided public ID."
    parameters: dict = {
        "type": "object",
        "properties": {
            "cid": {
                "type": "string",
                "description": "The Content Identifier (CID) of the object to share"
            },
            "public_id": {
                "type": "string",
                "description": "The public ID to use for sharing the object"
            }
        },
        "required": ["cid", "public_id"]
    }

    async def execute(self, cid: str, public_id: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.share_object(cid, public_id)
                return ToolResult(output=f"Object shared successfully with public ID: {public_id}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to share object: {str(e)}")

class GetObjectStatusTool(BaseTool):
    name: str = "get_object_status"
    description: str = "Get the status of an object by CID on Autonomys Auto Drive. This retrieves status information about the object."
    parameters: dict = {
        "type": "object",
        "properties": {
            "cid": {
                "type": "string",
                "description": "The Content Identifier (CID) of the object"
            }
        },
        "required": ["cid"]
    }

    async def execute(self, cid: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.get_object_status(cid)
                return ToolResult(output=f"Object status: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to get object status: {str(e)}")

class GetObjectMetadataTool(BaseTool):
    name: str = "get_object_metadata"
    description: str = "Get metadata for an object by CID on Autonomys Auto Drive. This retrieves detailed information about the object."
    parameters: dict = {
        "type": "object",
        "properties": {
            "cid": {
                "type": "string",
                "description": "The Content Identifier (CID) of the object"
            }
        },
        "required": ["cid"]
    }

    async def execute(self, cid: str) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.get_object_metadata(cid)
                return ToolResult(output=f"Object metadata: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to get object metadata: {str(e)}")
