from fastmcp import FastMCP
from .http_client import autonomys_auto_drive_client

mcp = FastMCP("AutonomysAutoDriveSubscriptions")

@mcp.tool()
async def get_subscriptions() -> dict:
    """
    Get current user subscription information.
    This is related to the user's payments, rights and interests at autonomys auto drive.
    Usually it is not needed to call this tool, unless the user explicitly asks for a call.
    {
      "subscription": {
        "id": "string",
        "organizationId": "string",
        "uploadLimit": 0,
        "downloadLimit": 0,
        "granularity": "monthly",
        "pendingUploadCredits": 0,
        "pendingDownloadCredits": 0
      }
    }
    """
    r = await autonomys_auto_drive_client.get(r'/subscriptions/@me')
    r = r.json()
    return r