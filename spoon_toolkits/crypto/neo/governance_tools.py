"""Governance and Committee Tools for Neo Blockchain"""

from spoon_ai.tools.base import BaseTool, ToolResult
from .base import get_provider


class GetCommitteeInfoTool(BaseTool):
    name: str = "get_committee_info"
    description: str = "Get detailed committee information for Neo blockchain governance. Useful when you need to understand governance structure or analyze committee composition and roles. Returns committee information."
    parameters: dict = {
        "type": "object",
        "properties": {
            "network": {
                "type": "string",
                "description": "Neo network type, must be 'mainnet' or 'testnet'",
                "enum": ["mainnet", "testnet"],
                "default": "testnet"
            }
        },
        "required": []
    }

    async def execute(self, network: str = "testnet") -> ToolResult:
        try:
            provider = get_provider(network)
            response = await provider._make_request("GetCommitteeInfo", {})
            result = provider._handle_response(response)
            return ToolResult(output=f"Committee info: {result}")
        except Exception as e:
            return ToolResult(error=str(e)) 