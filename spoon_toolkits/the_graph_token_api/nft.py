from fastmcp import FastMCP
from .http_client import the_graph_token_api_client
from .utils import normalize_ethereum_contract_address

mcp = FastMCP("TheGraphTokenApiNft")

@mcp.tool()
async def nft_activities(address: str, network_id: str = "mainnet"):
    """
    Get the NFT activities (transfers, mint and burns) of an NFT contract address.
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    {
      "data": [
        {
          "@type": "TRANSFER",
          "block_num": 22588725,
          "block_hash": "0xe8d2f48bb5d7619fd0c180d6d54e7ca94c5f4eddfcfa7a82d4da55b310dd462a",
          "timestamp": "2025-05-29 13:32:23",
          "tx_hash": "0xa7b3302a5fe4a60e4ece22dfb2d98604daef5dc610fa328d8d0a7a92f3efc7b9",
          "token_standard": "ERC721",
          "contract": "0xbd3531da5cf5857e7cfaa92426877b022e612cf8",
          "name": "PudgyPenguins",
          "symbol": "PPG",
          "from": "0x2afec1c9af7a5494503f8acfd5c1fdd7d2c57480",
          "to": "0x29469395eaf6f95920e59f858042f0e28d98a20b",
          "token_id": "500",
          "amount": 1,
          "transfer_type": "Single"
        }
      ]
    }
    """
    address = normalize_ethereum_contract_address(address)
    url = f"/nft/activities/evm?contract={address}&network_id={network_id}"
    resp = await the_graph_token_api_client.get(url)
    resp = resp.json()
    return resp

@mcp.tool()
async def nft_collection(address: str, network_id: str = "mainnet"):
    """
    Get a single NFT collection metadata, total supply, owners and total transfers
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    {
      "data": [
        {
          "token_standard": "ERC721",
          "contract": "0xbd3531da5cf5857e7cfaa92426877b022e612cf8",
          "contract_creation": "2021-07-22 12:26:01",
          "contract_creator": "0xe9da256a28630efdc637bfd4c65f0887be1aeda8",
          "name": "PudgyPenguins",
          "symbol": "PPG",
          "owners": 12258,
          "total_supply": 8888,
          "total_unique_supply": 8888,
          "total_transfers": 185128,
          "network_id": "mainnet"
        }
      ]
    }
    """
    address = normalize_ethereum_contract_address(address)
    url = f"/nft/collections/evm/{address}"
    resp = await the_graph_token_api_client.get(url)
    resp = resp.json()
    return resp

@mcp.tool()
async def nft_holders(address: str, network_id: str = "mainnet"):
    """
    Get holders of an NFT contract
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    {
      "data": [
        {
          "token_standard": "ERC721",
          "address": "0x29469395eaf6f95920e59f858042f0e28d98a20b",
          "quantity": 534,
          "unique_tokens": 534,
          "percentage": 0.06008100810081008,
          "network_id": "mainnet"
        }
      ]
    }
    """
    address = normalize_ethereum_contract_address(address)
    url = f"/nft/holders/evm/{address}?network_id={network_id}"
    resp = await the_graph_token_api_client.get(url)
    resp = resp.json()
    return resp

@mcp.tool()
async def nft_items(address: str, token_id: int, network_id: str = "mainnet"):
    """
    Get the metadata of an NFT token of a certain token_id
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    {
      "data": [
        {
          "token_standard": "ERC721",
          "contract": "0xbd3531da5cf5857e7cfaa92426877b022e612cf8",
          "token_id": "5712",
          "owner": "0x9379557bdf32f5ee296ca7b360ccb8dcb9543d8e",
          "uri": "ipfs://bafybeibc5sgo2plmjkq2tzmhrn54bk3crhnc23zd2msg4ea7a4pxrkgfna/5712",
          "name": "Pudgy Penguin #5712",
          "description": "A collection 8888 Cute Chubby Pudgy Penquins sliding around on the freezing ETH blockchain.",
          "image": "ipfs://QmNf1UsmdGaMbpatQ6toXSkzDpizaGmC9zfunCyoz1enD5/penguin/5712.png",
          "attributes": [
            {
              "trait_type": "Background",
              "value": "Blue"
            },
            {
              "trait_type": "Skin",
              "value": "Olive Green"
            },
            {
              "trait_type": "Body",
              "value": "Turtleneck Green"
            },
            {
              "trait_type": "Face",
              "value": "Scar"
            },
            {
              "trait_type": "Head",
              "value": "Party Hat"
            }
          ],
          "network_id": "mainnet"
        }
      ]
    }
    """
    address = normalize_ethereum_contract_address(address)
    url = f"/nft/items/evm/contract/{address}/token_id/{token_id}?network_id={network_id}"
    resp = await the_graph_token_api_client.get(url)
    resp = resp.json()
    return resp

@mcp.tool()
async def nft_ownerships(address: str, network_id: str = "mainnet"):
    """
    Get the NFT ownership of an Ethereum account
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    {
      "data": [
        {
          "token_id": "12",
          "token_standard": "ERC721",
          "contract": "0x000386e3f7559d9b6a2f5c46b4ad1a9587d59dc3",
          "owner": "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
          "symbol": "BANC",
          "name": "Bored Ape Nike Club",
          "network_id": "mainnet"
        }
      ]
    }
    """
    address = normalize_ethereum_contract_address(address)
    url = f"/nft/ownerships/evm/{address}?network_id={network_id}"
    resp = await the_graph_token_api_client.get(url)
    resp = resp.json()
    return resp

@mcp.tool()
async def nft_sales(address: str, network_id: str = "mainnet"):
    """
    Get the latest NFT marketplace sales of an NFT contract address.
    network_id: arbitrum-one, avalanche, base, bsc, mainnet, matic, optimism, unichain
    {
      "data": [
        {
          "timestamp": "2025-05-29 07:52:47",
          "block_num": 22587041,
          "tx_hash": "0x6755df1514a066150357d454254e1ce6c1e043f873193125dc98d4c4417861ff",
          "token": "0xbd3531da5cf5857e7cfaa92426877b022e612cf8",
          "token_id": "6398",
          "symbol": "PPG",
          "name": "PudgyPenguins",
          "offerer": "0xf671888173bf2fe28d71fba3106cf36d10f470fe",
          "recipient": "0x43bf952762b087195b8ea70cf81cb6715b6bf5a9",
          "sale_amount": 10.0667234,
          "sale_currency": "ETH"
        }
      ]
    }
    """
    address = normalize_ethereum_contract_address(address)
    url = f"/nft/sales/evm?network_id={network_id}&contract={address}"
    resp = await the_graph_token_api_client.get(url)
    resp = resp.json()
    return resp