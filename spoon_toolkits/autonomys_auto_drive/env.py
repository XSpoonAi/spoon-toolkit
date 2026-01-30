import os
import dotenv
dotenv.load_dotenv()

AUTONOMYS_AUTO_DRIVE_API_KEY = os.environ.get('AUTONOMYS_AUTO_DRIVE_API_KEY', '')
AUTONOMYS_AUTO_DRIVE_AUTH_PROVIDER = os.environ.get('AUTONOMYS_AUTO_DRIVE_AUTH_PROVIDER', 'apikey')