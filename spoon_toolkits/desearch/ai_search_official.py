"""
AI Search tool using official Desearch SDK
"""

from fastmcp import FastMCP
try:
    from .cache import time_cache
except ImportError:
    from cache import time_cache
from typing import Dict, Any, List

mcp = FastMCP("AISearch")

@mcp.tool()
@time_cache()
async def search_ai_data(query: str, platforms: str = "web,reddit,wikipedia,youtube", limit: int = 10) -> Dict[str, Any]:
    """
    Search for AI-related data across multiple platforms using Desearch API.
    
    Args:
        query: Search query string
        platforms: Comma-separated list of platforms (web, reddit, wikipedia, youtube, twitter, arxiv)
        limit: Number of results per platform (minimum 10)
    
    Returns:
        Dictionary containing search results from all platforms
    """
    return await _search_ai_data_impl(query, platforms, limit)

async def _search_ai_data_impl(query: str, platforms: str = "web,reddit,wikipedia,youtube", limit: int = 10) -> Dict[str, Any]:
    """Implementation of search_ai_data function using official SDK"""
    try:
        from desearch_py import Desearch
        from env import DESEARCH_API_KEY
        
        # Ensure minimum limit
        limit = max(limit, 10)
        
        # Initialize Desearch client
        desearch = Desearch(api_key=DESEARCH_API_KEY)
        
        # Parse platforms
        platform_list = [p.strip() for p in platforms.split(",")]
        
        # Map platform names to SDK tool names
        tool_mapping = {
            'web': 'web',
            'reddit': 'reddit',
            'wikipedia': 'wikipedia',
            'youtube': 'youtube',
            'twitter': 'twitter',
            'arxiv': 'arxiv',
            'hackernews': 'hackernews'
        }
        
        # Filter valid tools
        valid_tools = [tool_mapping.get(p, p) for p in platform_list if p in tool_mapping]
        
        if not valid_tools:
            return {"error": "No valid platforms specified"}
        
        # Perform AI search
        result = desearch.ai_search(
            prompt=query,
            tools=valid_tools,
            count=limit,
            streaming=False
        )
        
        # Process results
        processed_results = {}
        for tool, tool_results in result.items():
            if tool_results and isinstance(tool_results, dict) and 'organic_results' in tool_results:
                organic_results = tool_results['organic_results']
                processed_results[tool] = {
                    'count': len(organic_results),
                    'results': organic_results
                }
            elif tool_results:
                processed_results[tool] = {
                    'count': len(tool_results) if isinstance(tool_results, list) else 1,
                    'results': tool_results
                }
        
        return {
            "query": query,
            "platforms": platform_list,
            "results": processed_results,
            "total_results": sum(r.get('count', 0) for r in processed_results.values())
        }
        
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
@time_cache()
async def search_social_media(query: str, platform: str = "twitter", limit: int = 10) -> Dict[str, Any]:
    """
    Search social media platforms for real-time information.
    
    Args:
        query: Search query string
        platform: Platform to search (twitter, reddit)
        limit: Number of results (minimum 10)
    
    Returns:
        Dictionary containing social media search results
    """
    return await _search_social_media_impl(query, platform, limit)

async def _search_social_media_impl(query: str, platform: str = "twitter", limit: int = 10) -> Dict[str, Any]:
    """Implementation of search_social_media function using official SDK"""
    try:
        from desearch_py import Desearch
        from env import DESEARCH_API_KEY
        
        # Ensure minimum limit
        limit = max(limit, 10)
        
        # Initialize Desearch client
        desearch = Desearch(api_key=DESEARCH_API_KEY)
        
        if platform.lower() == "twitter":
            result = desearch.basic_twitter_search(
                query=query,
                count=limit
            )
        elif platform.lower() == "reddit":
            # Use AI search for Reddit with specific tool
            result = desearch.ai_search(
                prompt=query,
                tools=["reddit"],
                count=limit,
                streaming=False
            )
            # Extract reddit results
            result = result.get('reddit_search', [])
        else:
            return {"error": f"Unsupported platform: {platform}"}
        
        return {
            "platform": platform,
            "query": query,
            "results": result,
            "count": len(result) if isinstance(result, list) else 1
        }
        
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
@time_cache()
async def search_academic(query: str, platform: str = "arxiv", limit: int = 10) -> Dict[str, Any]:
    """
    Search academic platforms for research papers and scholarly content.
    
    Args:
        query: Search query string
        platform: Platform to search (arxiv, wikipedia)
        limit: Number of results (minimum 10)
    
    Returns:
        Dictionary containing academic search results
    """
    return await _search_academic_impl(query, platform, limit)

async def _search_academic_impl(query: str, platform: str = "arxiv", limit: int = 10) -> Dict[str, Any]:
    """Implementation of search_academic function using official SDK"""
    try:
        from desearch_py import Desearch
        from env import DESEARCH_API_KEY
        
        # Ensure minimum limit
        limit = max(limit, 10)
        
        # Initialize Desearch client
        desearch = Desearch(api_key=DESEARCH_API_KEY)
        
        if platform.lower() == "arxiv":
            # Use AI search for ArXiv
            result = desearch.ai_search(
                prompt=query,
                tools=["arxiv"],
                count=limit,
                streaming=False
            )
            result = result.get('arxiv_search', [])
        elif platform.lower() == "wikipedia":
            # Use AI search for Wikipedia
            result = desearch.ai_search(
                prompt=query,
                tools=["wikipedia"],
                count=limit,
                streaming=False
            )
            result = result.get('wikipedia_search', [])
        else:
            return {"error": f"Unsupported platform: {platform}"}
        
        return {
            "platform": platform,
            "query": query,
            "results": result,
            "count": len(result) if isinstance(result, list) else 1
        }
        
    except Exception as e:
        return {"error": str(e)} 