import httpx
from .env import THE_GRAPH_TOKEN_API_JWT

async def raise_on_4xx_5xx(response):
    await response.aread()
    response.raise_for_status()


the_graph_token_api_client = httpx.AsyncClient(
    base_url='https://token-api.thegraph.com/'.removesuffix('/'),
    headers={'Authorization': f"Bearer {THE_GRAPH_TOKEN_API_JWT}"},
    event_hooks={'response': [raise_on_4xx_5xx]},
)