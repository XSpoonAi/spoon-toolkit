# https://mainnet.auto-drive.autonomys.xyz/api/docs
from fastmcp import FastMCP
from .subscriptions import mcp as subscriptions_server
from .objects import mcp as objects_server, mcp_management as managements_server
from .uploads import mcp as uploads_server

mcp_server = FastMCP("AutonomysAutoDriveServer")
mcp_server.mount(subscriptions_server, "Subscriptions")
mcp_server.mount(objects_server, "Downloads")
mcp_server.mount(managements_server, "Managements")
mcp_server.mount(uploads_server, "Uploads")