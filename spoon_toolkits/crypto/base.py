import json
import os
from typing import Optional
import requests
from pydantic import Field

from spoon_ai.tools.base import BaseTool

BITQUERY_API_KEY = os.getenv("BITQUERY_API_KEY")
BITQUERY_CLIENT_ID = os.getenv("BITQUERY_CLIENT_ID")
BITQUERY_CLIENT_SECRET = os.getenv("BITQUERY_CLIENT_SECRET")

class DefiBaseTool(BaseTool):
    """Base class for all DeFi tools"""
    name: str = Field(description="The name of the tool")
    description: str = Field(description="A description of the tool")
    parameters: dict = Field(description="The parameters of the tool")

class BitqueryTool(DefiBaseTool):
    """Base class for tools that use Bitquery API"""
    bitquery_endpoint: str = "https://streaming.bitquery.io/graphql"
    graph_template: Optional[str] = Field(default=None, description="The GraphQL template of the tool")

    def oAuth(self):
        """Authenticate with Bitquery OAuth"""
        # Check if required environment variables are set
        if not BITQUERY_CLIENT_ID or not BITQUERY_CLIENT_SECRET:
            raise ValueError(
                "Bitquery OAuth credentials are not configured. Please set the following environment variables:\n"
                "- BITQUERY_CLIENT_ID: Your Bitquery client ID\n"
                "- BITQUERY_CLIENT_SECRET: Your Bitquery client secret\n\n"
                "To obtain these credentials:\n"
                "1. Visit https://bitquery.io/\n"
                "2. Sign up for an account or log in\n"
                "3. Go to your dashboard and create an OAuth application\n"
                "4. Copy the Client ID and Client Secret\n"
                "5. Add them to your .env file:\n"
                "   BITQUERY_CLIENT_ID=your_client_id_here\n"
                "   BITQUERY_CLIENT_SECRET=your_client_secret_here\n\n"
                "Manage your credentials at: https://bitquery.io/dashboard"
            )

        url = "https://oauth2.bitquery.io/oauth2/token"
        payload = f'grant_type=client_credentials&client_id={BITQUERY_CLIENT_ID}&client_secret={BITQUERY_CLIENT_SECRET}&scope=api'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        try:
            response = requests.request("POST", url, headers=headers, data=payload)
            response.raise_for_status()
            resp = json.loads(response.text)

            if 'access_token' not in resp:
                raise ValueError(
                    "Failed to obtain access token from Bitquery. Please check your credentials.\n"
                    "Make sure your BITQUERY_CLIENT_ID and BITQUERY_CLIENT_SECRET are correct.\n"
                    "You can verify your credentials at https://bitquery.io/dashboard"
                )

            return {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {resp['access_token']}"
            }
        except requests.exceptions.RequestException as e:
            raise ValueError(
                f"Failed to authenticate with Bitquery API: {e}\n"
                "Please check your internet connection and verify your credentials at https://bitquery.io/dashboard"
            )

    async def execute(self, **kwargs) -> str:
        """Execute GraphQL query using Bitquery API"""
        graph = self.graph_template.format(**kwargs)
        response = requests.post(self.bitquery_endpoint, json={"query": graph}, headers=self.oAuth())
        if response.status_code != 200:
            raise Exception(f"Failed to execute tool: {response.text}")
        return response.json()

# For backward compatibility, keep DexBaseTool as an alias to BitqueryTool
DexBaseTool = BitqueryTool
