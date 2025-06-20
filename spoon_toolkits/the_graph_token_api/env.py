import os
import dotenv
dotenv.load_dotenv()

THE_GRAPH_TOKEN_API_JWT = os.environ.get('THE_GRAPH_TOKEN_API_JWT', "eyJh...")
