"""
Web Search tool using official Desearch SDK
"""

from fastmcp import FastMCP
try:
    from .cache import time_cache
except ImportError:
    from cache import time_cache
from typing import Dict, Any, List

mcp = FastMCP("WebSearch")

@mcp.tool()
@time_cache()
async def search_web(query: str, num_results: int = 10, start: int = 0) -> Dict[str, Any]:
    """
    Search the web for information using Desearch API.
    
    Args:
        query: Search query string
        num_results: Number of results to return (default 10)
        start: Starting position for pagination (default 0)
    
    Returns:
        Dictionary containing web search results
    """
    return await _search_web_impl(query, num_results, start)

async def _search_web_impl(query: str, num_results: int = 10, start: int = 0) -> Dict[str, Any]:
    """Implementation of search_web function using official SDK"""
    try:
        from desearch_py import Desearch
        from env import DESEARCH_API_KEY
        
        # Initialize Desearch client
        desearch = Desearch(api_key=DESEARCH_API_KEY)
        
        # Perform web search
        result = desearch.basic_web_search(
            query=query,
            num=num_results,
            start=start
        )
        
        # Process results
        if 'data' in result:
            data = result['data']
            return {
                "query": query,
                "results": data,
                "count": len(data),
                "start": start,
                "total_results": len(data)
            }
        else:
            return {
                "query": query,
                "results": [],
                "count": 0,
                "start": start,
                "total_results": 0,
                "error": "No data in response"
            }
        
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
@time_cache()
async def search_twitter_links(query: str, limit: int = 10) -> Dict[str, Any]:
    """
    Search for links shared on Twitter using Desearch API.
    
    Args:
        query: Search query string
        limit: Number of results to return (minimum 10)
    
    Returns:
        Dictionary containing Twitter links search results
    """
    return await _search_twitter_links_impl(query, limit)

async def _search_twitter_links_impl(query: str, limit: int = 10) -> Dict[str, Any]:
    """Implementation of search_twitter_links function using official SDK"""
    try:
        from desearch_py import Desearch
        from env import DESEARCH_API_KEY
        
        # Ensure minimum limit
        limit = max(limit, 10)
        
        # Initialize Desearch client
        desearch = Desearch(api_key=DESEARCH_API_KEY)
        
        # Perform Twitter links search
        result = desearch.twitter_links_search(
            prompt=query,
            count=limit
        )
        
        # Process results
        processed_results = {}
        for key, value in result.items():
            if isinstance(value, list):
                processed_results[key] = {
                    'count': len(value),
                    'results': value
                }
            else:
                processed_results[key] = {
                    'count': 1,
                    'results': value
                }
        
        return {
            "query": query,
            "results": processed_results,
            "total_results": sum(r.get('count', 0) for r in processed_results.values())
        }
        
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
@time_cache()
async def search_twitter_posts(query: str, limit: int = 10, sort: str = "Top") -> Dict[str, Any]:
    """
    Search for Twitter posts using Desearch API.
    
    Args:
        query: Search query string
        limit: Number of results to return (minimum 10)
        sort: Sort order (Top, Latest, etc.)
    
    Returns:
        Dictionary containing Twitter posts search results
    """
    return await _search_twitter_posts_impl(query, limit, sort)

async def _search_twitter_posts_impl(query: str, limit: int = 10, sort: str = "Top") -> Dict[str, Any]:
    """Implementation of search_twitter_posts function using official SDK"""
    try:
        from desearch_py import Desearch
        from env import DESEARCH_API_KEY
        
        # Ensure minimum limit
        limit = max(limit, 10)
        
        # Initialize Desearch client
        desearch = Desearch(api_key=DESEARCH_API_KEY)
        
        # Perform Twitter search
        result = desearch.basic_twitter_search(
            query=query,
            count=limit,
            sort=sort
        )
        
        return {
            "query": query,
            "sort": sort,
            "results": result,
            "count": len(result) if isinstance(result, list) else 1
        }
        
    except Exception as e:
        return {"error": str(e)} 