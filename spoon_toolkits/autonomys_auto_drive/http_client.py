import httpx
from .env import AUTONOMYS_AUTO_DRIVE_API_KEY, AUTONOMYS_AUTO_DRIVE_AUTH_PROVIDER

async def raise_on_4xx_5xx(response):
    await response.aread()
    response.raise_for_status()


autonomys_auto_drive_client = httpx.AsyncClient(
    base_url='https://mainnet.auto-drive.autonomys.xyz/api'.removesuffix('/'),
    headers={'Authorization': f"Bearer {AUTONOMYS_AUTO_DRIVE_API_KEY}",
             'X-Auth-Provider': AUTONOMYS_AUTO_DRIVE_AUTH_PROVIDER},
    event_hooks={'response': [raise_on_4xx_5xx]},
)
