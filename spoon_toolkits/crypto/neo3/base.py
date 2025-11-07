"""Base module for Neo N3 blockchain tools"""

from .neo3_provider import Neo3Provider

def get_provider(network: str = "testnet") -> Neo3Provider:
    """Get Neo N3 provider instance
    
    Args:
        network (str): The Neo network to connect to. Must be 'mainnet' or 'testnet'
    
    Returns:
        Neo3Provider: A Neo N3 provider instance
    """
    return Neo3Provider(network)

