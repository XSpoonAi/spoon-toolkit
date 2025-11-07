# Spoon Toolkits

Spoon Toolkits is a comprehensive collection of blockchain and cryptocurrency tools that provides various specialized functional modules for SpoonAI. These tools cover multiple domains including security detection, price data, storage services, blockchain interaction, and more.

## 📁 Module Overview

### 🔒 GoPlusLabs - Security Detection Tools
**Path**: `gopluslabs/`

The GoPlusLabs module provides comprehensive blockchain security detection services, including:

- **Token Security Detection** (`token_security.py`)
  - Detect security risks in token contracts
  - Support for Ethereum and Solana networks
  - Detect honeypots, fake tokens, blacklisted addresses, and other risks

- **Malicious Address Detection** (`malicious_address.py`)
  - Identify known malicious addresses
  - Provide address risk assessment

- **NFT Security Detection** (`nft_security.py`)
  - NFT contract security analysis
  - Detect NFT-related risks

- **DApp Security Detection** (`dapp_security.py`)
  - Decentralized application security assessment
  - Smart contract risk analysis

- **Phishing Site Detection** (`phishing_site.py`)
  - Identify phishing websites
  - Provide website security assessment

- **Rug Pull Detection** (`rug_pull_detection.py`)
  - Detect potential rug pull risks
  - Project credibility assessment

- **Approval Security Detection** (`approval_security.py`)
  - Detect token approval risks
  - Analyze approval security

- **Supported Chains** (`supported_chains.py`)
  - Get list of supported blockchain networks
  - Chain ID and name mapping

### 💰 Crypto - Cryptocurrency Data Tools
**Path**: `crypto/`

Provides comprehensive cryptocurrency market data and analysis tools:

- **Price Data** (`price_data.py`)
  - Real-time token price retrieval
  - Support for DEXs like Uniswap and Raydium
  - K-line data and 24-hour statistics

- **Price Alerts** (`price_alerts.py`)
  - Price threshold monitoring
  - Liquidity range checking
  - Abnormal price movement detection

- **Lending Rates** (`lending_rates.py`)
  - DeFi lending protocol rate monitoring
  - Yield comparison analysis

- **LST Arbitrage** (`lst_arbitrage.py`)
  - Liquid staking token arbitrage opportunities
  - Cross-protocol yield analysis

- **Blockchain Monitoring** (`blockchain_monitor.py`)
  - Blockchain network status monitoring
  - Transaction pool monitoring

- **Token Holder Analysis** (`token_holders.py`)
  - Token holder distribution analysis
  - Whale address tracking

- **Trading History** (`trading_history.py`)
  - Transaction record queries
  - Historical data analysis

- **Wallet Analysis** (`wallet_analysis.py`)
  - Wallet behavior analysis
  - Portfolio analysis

- **Uniswap Liquidity** (`uniswap_liquidity.py`)
  - Uniswap liquidity pool analysis
  - LP yield calculation

### 📊 Crypto PowerData - Advanced Cryptocurrency Data & Indicators Tools
**Path**: `crypto_powerdata/`

Provides advanced cryptocurrency market data and technical analysis tools:

- **CEX Data with Indicators** (`CryptoPowerDataCEXTool`)
  - Fetch candlestick data from 100+ centralized exchanges (e.g., Binance, Coinbase, Kraken)
  - Apply comprehensive technical indicators (e.g., EMA, MACD, RSI)

- **DEX Data with Indicators** (`CryptoPowerDataDEXTool`)
  - Fetch candlestick data from decentralized exchanges via OKX DEX API
  - Apply comprehensive technical indicators for on-chain data
  - **Note**: To use crypto powerdata DEX query functionality, you need to obtain OKX API credentials from [OKX Web3 Developer Portal](https://web3.okx.com/build/dev-portal)

- **Real-time Price Retrieval** (`CryptoPowerDataPriceTool`)
  - Get real-time cryptocurrency prices from both CEX and DEX sources

- **Indicators Listing** (`CryptoPowerDataIndicatorsTool`)
  - List all available technical indicators and their configurations

- **MCP Server Support**
  - Can run as a Multi-Chain Protocol (MCP) server for enhanced data streaming and integration

### 🌐 Neo - Neo Blockchain Tools
**Path**: `neo/`

Specialized toolkit for Neo blockchain:

- **Complete Neo N3 API Toolkit** (`tool_collection.py`)
  - Address information queries
  - Asset information retrieval
  - Block and transaction queries
  - Smart contract interaction
  - Voting and governance functions
  - NEP-11/NEP-17 token operations

- **GitHub Analysis** (`github_analysis.py`)
  - Neo ecosystem project GitHub analysis
  - Code quality assessment

- **Vote Queries** (`getScVoteCallByVoterAddress.py`)
  - Voter address queries
  - Governance participation analysis

### 🌐 ThirdWeb - Web3 Development Tools
**Path**: `third_web/`

Blockchain data tools based on ThirdWeb Insight API:

- **Contract Event Queries** - Retrieve specific contract event logs
- **Multi-chain Transfer Queries** - Cross-chain transfer record queries
- **Transaction Data Retrieval** - Multi-chain transaction data retrieval
- **Contract Transaction Analysis** - Specific contract transaction analysis
- **Block Data Queries** - Block information retrieval
- **Wallet Transaction History** - Wallet address transaction records

### 🔍 Chainbase - Blockchain Data API Tools
**Path**: `chainbase/`

Comprehensive blockchain data query tools based on Chainbase API:

#### Chainbase Tools (`chainbase_tools.py`)
- **GetLatestBlockNumberTool** - Get the latest block height of blockchain network
- **GetBlockByNumberTool** - Get the block by number of blockchain network
- **GetTransactionByHashTool** - Get the transaction by hash of blockchain network
- **GetAccountTransactionsTool** - Returns the transactions from a specific wallet address
- **ContractCallTool** - Calls a specific function for the specified contract
- **GetAccountTokensTool** - Retrieve all token balances for all ERC20 tokens for a specified address
- **GetAccountNFTsTool** - Get the list of NFTs owned by an account
- **GetAccountBalanceTool** - Returns the native token balance for a specified address
- **GetTokenMetadataTool** - Get the metadata of a specified token

#### Balance Module (`balance.py`)
- **Account Token Balances** - Retrieve all ERC20 token balances for an address
- **Account NFT Holdings** - Get the list of NFTs owned by an account
- **Native Token Balance** - Query native token balance for an address

#### Basic Blockchain Module (`basic.py`)
- **Block Data Queries** - Get latest block number and block details
- **Transaction Data** - Retrieve transaction details by hash or block position
- **Account Transactions** - Get transaction history for an address
- **Contract Function Calls** - Execute read-only contract function calls

#### Token API Module (`token_api.py`)
- **Token Metadata** - Retrieve token contract metadata
- **Token Holders Analysis** - Get token holder distribution and top holders
- **Token Price Data** - Current and historical token price information
- **Token Transfer History** - Track ERC20 token transfers

### 💾 Storage - Decentralized Storage Tools
**Path**: `storage/`

Provides multiple decentralized storage solutions:

#### Base Storage Tools (`base_storge_tool.py`)
- S3-compatible storage interface
- Support for bucket operations, object upload/download
- Multipart upload support
- Pre-signed URL generation

#### AIOZ Storage (`aioz/`)
- AIOZ network storage services
- Decentralized content distribution

#### 4EVERLAND Storage (`foureverland/`)
- 4EVERLAND decentralized storage
- IPFS-compatible interface

#### OORT Storage (`oort/`)
- OORT decentralized cloud storage
- Enterprise-grade storage solutions

### 🔄 Token Execute - Token Execution Tools
**Path**: `token_execute/`

Token operation and execution tools:

- **Base Tools** (`base.py`) - Token operation base class
- **Token Transfer** (`token_transfer.py`) - Token transfer functionality

## 🚀 Quick Start

### Requirements

```bash
# Install dependencies
pip install -r requirements.txt
```

### Environment Variable Configuration

Create a `.env` file in your project root or set these environment variables:

```bash
# GoPlusLabs API
export GOPLUS_API_KEY="your_api_key"

# ThirdWeb
export THIRDWEB_CLIENT_ID="your_client_id"

# RPC Node
export RPC_URL="your_rpc_url"

# Chainbase API
export CHAINBASE_API_KEY="your_api_key"
export CHAINBASE_HOST="0.0.0.0"  # Optional, default is 0.0.0.0
export CHAINBASE_PORT="8000"     # Optional, default is 8000
export CHAINBASE_PATH="/sse"     # Optional, default is /sse

# Bitquery API (for blockchain data analysis)
export BITQUERY_API_KEY="your_api_key"
export BITQUERY_CLIENT_ID="your_client_id"
export BITQUERY_CLIENT_SECRET="your_client_secret"

# OKX API Configuration (for Crypto PowerData DEX queries)
export OKX_API_KEY="your_okx_api_key"
export OKX_SECRET_KEY="your_okx_secret_key"
export OKX_API_PASSPHRASE="your_okx_api_passphrase"
export OKX_PROJECT_ID="your_okx_project_id"

# Storage Service Configuration
export AIOZ_ACCESS_KEY="your_access_key"
export AIOZ_SECRET_KEY="your_secret_key"
export FOUREVERLAND_ACCESS_KEY="your_access_key"
export FOUREVERLAND_SECRET_KEY="your_secret_key"
export OORT_ACCESS_KEY="your_access_key"
export OORT_SECRET_KEY="your_secret_key"

# GitHub API Configuration
export GITHUB_TOKEN="your_github_personal_access_token"
```

### 🔑 API Setup Guides

For detailed setup instructions for specific services:

- **Bitquery API**: See [docs/BITQUERY_SETUP.md](docs/BITQUERY_SETUP.md) for comprehensive setup instructions
- **GoPlusLabs**: Visit [https://gopluslabs.io/](https://gopluslabs.io/) to get your API key
- **Chainbase**: Visit [https://chainbase.com/](https://chainbase.com/) to get your API key
- **GitHub** Visit [https://github.com/settings/tokens](https://github.com/settings/tokens) to get your API key

> **⚠️ Important**: If you encounter authentication errors when using any tools, the system will provide detailed instructions on where to obtain the required API credentials and how to configure them.

### Usage Examples

#### 1. Token Security Detection

```python
from spoon_toolkits.gopluslabs.token_security import get_token_risk_and_security_data

# Detect Ethereum token security
result = await get_token_risk_and_security_data(
    chain_name="ethereum",
    contract_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
)
```

#### 2. Get Token Price

```python
from spoon_toolkits.crypto.price_data import GetTokenPriceTool

tool = GetTokenPriceTool()
result = await tool.execute(symbol="ETH-USDC", exchange="uniswap")
```

#### 3. Neo Blockchain Query

```python
from spoon_toolkits.crypto.neo import NeoProvider

# Query Neo address information
async def get_address_info_example():
    provider = NeoProvider(network="testnet")  # or "mainnet"
    address_info = await provider.get_address_info("NiEtVMWVYgpXrWkRTMwRaMJtJ41gD3912N")
    await provider.close()  # Clean up connection
    return address_info
```

#### 4. Decentralized Storage

```python
from spoon_toolkits.storage.aioz.aioz_tools import AiozStorageTool

tool = AiozStorageTool()
result = await tool.upload_file(bucket_name="my-bucket", file_path="./file.txt")
```

#### 5. Chainbase Tools

```python
from spoon_toolkits.chainbase import GetLatestBlockNumberTool, GetAccountBalanceTool

# Get the latest Ethereum block
block_tool = GetLatestBlockNumberTool()
block_result = await block_tool.execute(chain_id=1)
print(f"Latest Block: {block_result}")

# Get account ETH balance
balance_tool = GetAccountBalanceTool()
balance_result = await balance_tool.execute(
    chain_id=1,
    address="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # vitalik.eth
)
print(f"Account Balance: {balance_result}")
```

#### 6. Crypto PowerData Usage

```python
from spoon_toolkits.crypto_powerdata import CryptoPowerDataCEXTool, CryptoPowerDataPriceTool

# Get CEX data with EMA and RSI indicators
cex_tool = CryptoPowerDataCEXTool()
cex_data = await cex_tool.execute(
    exchange="binance",
    symbol="BTC/USDT",
    timeframe="1d",
    limit=100,
    indicators_config='{\"ema\": [{\"timeperiod\": 12}, {\"timeperiod\": 26}], \"rsi\": [{\"timeperiod\": 14}]}'
)
print(f"CEX Data with Indicators: {cex_data}")

# Get DEX data with indicators
dex_tool = CryptoPowerDataDEXTool()
dex_data = await dex_tool.execute(
    chain_index="1",  # Ethereum
    token_address="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
    timeframe="1h",
    limit=100,
    indicators_config='{"ema": [{"timeperiod": 12}, {"timeperiod": 26}], "rsi": [{"timeperiod": 14}]}'
)
print(f"DEX Data with Indicators: {dex_data}")

# Get real-time DEX token price
price_tool = CryptoPowerDataPriceTool()
dex_price = await price_tool.execute(
    source="dex",
    chain_index="1",  # Ethereum
    token_address="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"  # WETH
)
print(f"DEX Token Price: {dex_price}")
```

## 🔧 Tool Features

### 🛡️ Security
- Comprehensive security detection coverage
- Multi-dimensional risk assessment
- Real-time threat detection

### 📊 Data Richness
- Multi-chain data support
- Real-time price and market data
- Historical data analysis

### 🌐 Multi-chain Support
- Ethereum ecosystem
- Solana ecosystem
- Neo blockchain
- Other EVM-compatible chains

### 🔄 Easy Integration
- Unified tool interface
- Asynchronous operation support
- Detailed error handling

## 📖 API Documentation

Each module provides detailed API documentation and usage examples. Please refer to the source code comments in each module directory for specific documentation.

## 🤝 Contributing

1. Fork the project
2. Create a feature branch
3. Commit your changes
4. Create a Pull Request

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

## 🆘 Support

For questions or suggestions, please submit an Issue or contact the development team.

---

**Note**: When using these tools, please ensure that you have properly configured the relevant API keys and environment variables. Some features may require paid API services.