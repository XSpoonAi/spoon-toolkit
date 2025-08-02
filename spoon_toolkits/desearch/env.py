import os
import dotenv
dotenv.load_dotenv()

# Required API key
DESEARCH_API_KEY = os.environ.get('DESEARCH_API_KEY', '')

# Optional configuration (for future use)
DESEARCH_BASE_URL = os.environ.get('DESEARCH_BASE_URL', 'https://api.desearch.ai')
DESEARCH_TIMEOUT = int(os.environ.get('DESEARCH_TIMEOUT', '30')) 