"""Account-related tools for Autonomys Auto Drive"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider
from .provider import AutoDriveAPIError

class GetAccountInfoTool(BaseTool):
    name: str = "get_account_info"
    description: str = "Get current user account information from Autonomys Auto Drive. Useful for checking storage limits and credit status."
    parameters: dict = {
        "type": "object",
        "properties": {},
        "required": []
    }

    async def execute(self) -> ToolResult:
        try:
            async with get_provider() as provider:
                result = await provider.get_account_info()
                return ToolResult(output=f"Account info: {result}")
        except AutoDriveAPIError as e:
            return ToolResult(error=f"API Error: {str(e)}")
        except RuntimeError as e:
            return ToolResult(error=str(e))
        except Exception as e:
            return ToolResult(error=f"Failed to get account info: {str(e)}")
