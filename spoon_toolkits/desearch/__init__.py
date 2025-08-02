"""
Desearch AI Integration for Spoon Framework
"""

from fastmcp import FastMCP

# Import sub-servers with fallback for standalone execution
try:
    from .ai_search_official import mcp as ai_search_server
    from .web_search_official import mcp as web_search_server
except ImportError:
    # Fallback for standalone execution
    from ai_search_official import mcp as ai_search_server
    from web_search_official import mcp as web_search_server

# Create main MCP server
mcp_server = FastMCP("DesearchServer")

# Mount sub-servers (using new syntax)
mcp_server.mount(ai_search_server)
mcp_server.mount(web_search_server)

# Export main functions for direct use
try:
    from .ai_search_official import (
        search_ai_data,
        search_social_media,
        search_academic
    )

    from .web_search_official import (
        search_web,
        search_twitter_links,
        search_twitter_posts
    )
except ImportError:
    # Fallback for standalone execution
    from ai_search_official import (
        search_ai_data,
        search_social_media,
        search_academic
    )

    from web_search_official import (
        search_web,
        search_twitter_links,
        search_twitter_posts
    )

__all__ = [
    "mcp_server",
    "search_ai_data",
    "search_social_media", 
    "search_academic",
    "search_web",
    "search_twitter_links",
    "search_twitter_posts"
]

if __name__ == "__main__":
    mcp_server.run() 