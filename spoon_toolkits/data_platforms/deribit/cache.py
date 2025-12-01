"""Cache decorator for Deribit API responses"""

import functools
import time
from typing import Any, Callable, Dict, Optional
from .env import DeribitConfig

# Simple in-memory cache (can be replaced with Redis, etc. in the future)
_cache: Dict[str, tuple[Any, float]] = {}


def time_cache(ttl: Optional[int] = None):
    """
    Decorator to cache function results with time-based expiration
    
    Args:
        ttl: Time to live in seconds (defaults to config)
        
    Example:
        @time_cache(ttl=300)
        async def get_instruments(currency: str):
            ...
    """
    ttl = ttl or DeribitConfig.CACHE_TTL
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Generate cache key from function name and arguments
            cache_key = f"{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
            
            # Check cache
            if cache_key in _cache:
                result, expires_at = _cache[cache_key]
                if time.time() < expires_at:
                    return result
            
            # Call function and cache result
            result = await func(*args, **kwargs)
            _cache[cache_key] = (result, time.time() + ttl)
            
            return result
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = f"{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
            
            # Check cache
            if cache_key in _cache:
                result, expires_at = _cache[cache_key]
                if time.time() < expires_at:
                    return result
            
            # Call function and cache result
            result = func(*args, **kwargs)
            _cache[cache_key] = (result, time.time() + ttl)
            
            return result
        
        # Return appropriate wrapper based on function type
        if hasattr(func, '__code__') and 'async' in str(func.__code__.co_flags):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def clear_cache():
    """Clear all cached data"""
    global _cache
    _cache.clear()


def get_cache_size() -> int:
    """Get number of cached items"""
    return len(_cache)

