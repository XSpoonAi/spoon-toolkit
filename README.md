# Spoon Toolkits

Spoon Toolkits is a comprehensive collection of blockchain and cryptocurrency tools that provides various specialized functional modules for SpoonAI. These tools cover multiple domains including security detection, price data, storage services, blockchain interaction, audio/voice AI, and more.

## 📁 Module Overview

### 🎙️ Audio - AI Voice & Audio Tools

**Path**: `audio/`

AI-powered audio tools for speech synthesis, transcription, voice cloning, and localization:

- **Text-to-Speech** (`ElevenLabsTextToSpeechTool`)

  - Convert text to high-quality speech in 70+ languages
  - Multiple voice options (5000+ voices)
  - Streaming with character-level timestamps

- **Speech-to-Text** (`ElevenLabsSpeechToTextTool`)

  - Transcribe audio/video files to text
  - 99 language support with auto-detection
  - Industry-leading accuracy

- **Voice Design** (`ElevenLabsVoiceDesignTool`)

  - Generate custom voices from text descriptions
  - Create unique voices for agents and applications
  - Preview and save designed voices

- **Voice Cloning** (`ElevenLabsInstantVoiceCloneTool`)

  - Clone voices from 1-3 audio samples
  - Instant voice creation
  - Background noise removal

- **Dubbing** (`ElevenLabsDubbingCreateTool`)
  - Localize audio/video content to different languages
  - Automatic dubbing with voice matching
  - Download dubbed audio files

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

### EVM Blockchain Tools (`crypto/evm/`)

Comprehensive EVM-compatible blockchain interaction tools:

- **Balance Query** (`balance.py`)

  - Query native token (ETH, MATIC, etc.) balances
  - Query ERC20 token balances
  - Multi-chain support (Ethereum, Polygon, Arbitrum, Base, etc.)

- **Native Token Transfer** (`transfer.py`)

  - Transfer native tokens (ETH, MATIC, etc.) on EVM chains
  - Support for local private key signing
  - Support for Turnkey secure signing
  - Gas price optimization

- **ERC20 Token Transfer** (`erc20.py`)

  - Transfer ERC20 tokens on EVM chains
  - Automatic token approval handling
  - Support for local and Turnkey signing

- **Token Swap** (`swap.py`)

  - Swap tokens on the same EVM chain via Bebop aggregator
  - Automatic token approval handling
  - Slippage protection
  - Support for local and Turnkey signing

- **Swap Quote** (`quote.py`)

  - Get swap quotes without executing transactions
  - Compare quotes from multiple aggregators (Bebop, LiFi)
  - Price impact analysis
  - Route optimization

- **Cross-Chain Bridge** (`bridge.py`)

  - Cross-chain token bridging via LiFi aggregator
  - Support for multiple EVM chains
  - Bridge route optimization

- **Signer Management** (`signers.py`)
  - Unified signing interface for EVM transactions
  - Local private key signing via web3.py
  - Turnkey API integration for enhanced security
  - Automatic signer selection based on configuration

### Solana Blockchain Tools (`crypto/solana/`)

Complete Solana blockchain interaction toolkit:

- **Wallet Information** (`wallet.py`)

  - Query SOL balance and token holdings
  - Token account information
  - Portfolio overview with price data

- **SOL Transfer** (`transfer.py`)

  - Transfer native SOL tokens
  - Support for devnet, testnet, and mainnet
  - Transaction fee estimation

- **Token Swap** (`swap.py`)

  - Swap tokens on Solana via Jupiter aggregator
  - Support for native SOL and SPL tokens
  - Route optimization and slippage protection
  - Priority fee configuration

- **Blockchain Service** (`service.py`)

  - Comprehensive Solana RPC interaction
  - Wallet data caching and refresh
  - Token balance queries
  - Transaction error parsing
  - Address validation utilities

- **Keypair Utilities** (`keypairUtils.py`)

  - Wallet keypair generation and management
  - Private key handling
  - Public key derivation

- **Environment Configuration** (`environment.py`)
  - Solana network configuration
  - RPC URL management
  - Environment variable handling

### Memory Management Tools (`memory/`)

Long-term memory management powered by Mem0:

- **Add Memory** (`mem0_tools.py` - `AddMemoryTool`)

  - Store text or conversation snippets
  - Support for structured messages
  - Metadata and filtering support

- **Search Memory** (`mem0_tools.py` - `SearchMemoryTool`)

  - Natural language memory search
  - Semantic similarity search
  - Configurable result limits

- **Get All Memories** (`mem0_tools.py` - `GetAllMemoryTool`)

  - Retrieve all stored memories for a user/agent
  - Filtering and pagination support
  - Metadata-based queries

- **Update Memory** (`mem0_tools.py` - `UpdateMemoryTool`)

  - Update existing memory entries
  - Modify content and metadata
  - Selective memory updates

- **Delete Memory** (`mem0_tools.py` - `DeleteMemoryTool`)
  - Remove specific memory entries
  - Bulk deletion support
  - Filter-based deletion

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

### 🌐 Neo3 - Neo N3 Blockchain Tools (Official RPC Methods Only)
**Path**: `neo3/`

Neo N3 blockchain tools using **only official RPC API methods** as documented at [developers.neo.org](https://developers.neo.org/docs/n3/reference/rpc/api).

**Key Features:**
- ✅ **22 Tools** covering all official Neo N3 RPC methods
- ✅ **100% Compatibility** with any Neo N3 RPC node
- ✅ **No Third-Party Dependencies** - only official RPC methods
- ✅ **Comprehensive Testing** - dedicated test file for each tool module

**Available Tool Categories:**
- **Block Tools** (6) - Block queries, headers, hashes
- **Transaction Tools** (4) - Transaction data, mempool, application logs
- **NEP Tools** (5) - NEP-17 and NEP-11 token operations
- **Contract Tools** (4) - Contract state, storage, function invocation
- **Governance Tools** (2) - Committee and validators
- **Utility Tools** (1) - Address validation

**Usage Example:**
```python
from spoon_toolkits.crypto.neo3 import (
    GetBlockCountTool,
    GetNep17BalancesTool,
    GetContractStateTool,
    Neo3Provider
)

# Use tools
tool = GetBlockCountTool()
result = await tool.execute("mainnet")

# Or use provider directly
provider = Neo3Provider(network="mainnet")
block_count = await provider.get_block_count()
```

See [neo3/README.md](spoon_toolkits/crypto/neo3/README.md) for complete documentation and usage examples.

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
pip install -e .
```

### Environment Variable Configuration

Create a `.env` file in your project root or set these environment variables:

```bash
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

# ElevenLabs Audio API (for TTS, STT, voice cloning, dubbing)
export ELEVENLABS_API_KEY="your_elevenlabs_api_key"  # Get at https://elevenlabs.io/app/settings/api-keys

# EVM Blockchain Configuration
export EVM_PRIVATE_KEY="0x..."  # Private key for local signing (optional)
export TURNKEY_API_PUBLIC_KEY="your_turnkey_public_key"  # Turnkey API credentials (optional)
export TURNKEY_API_PRIVATE_KEY="your_turnkey_private_key"
export TURNKEY_ORG_ID="your_turnkey_org_id"
export TURNKEY_SIGN_WITH="your_turnkey_signer_id"
export TURNKEY_ADDRESS="0x..."  # Turnkey signer address

# Solana Blockchain Configuration
export SOLANA_PRIVATE_KEY="your_base58_private_key"  # Solana wallet private key (Base58 encoded)
export SOLANA_PUBLIC_KEY="your_public_key"  # Optional: Solana wallet public key

# Mem0 Memory Configuration
export MEM0_API_KEY="your_mem0_api_key"  # Mem0 API key for long-term memory
export MEM0_PROJECT_ID="your_mem0_project_id"  # Optional: Mem0 project ID
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
from spoon_toolkits.neo.tool_collection import getAddressInfoByAddress

# Query Neo address information
address_info = getAddressInfoByAddress("NiEtVMWVYgpXrWkRTMwRaMJtJ41gD3912N")
```

#### 3b. Neo3 Blockchain Query (Official RPC Methods Only)

```python
import asyncio
from spoon_toolkits.crypto.neo3 import (
    GetBlockCountTool,
    GetNep17BalancesTool,
    Neo3Provider
)

async def neo3_example():
    # Using tools
    block_tool = GetBlockCountTool()
    result = await block_tool.execute("mainnet")
    print(f"Block count: {result.output}")
    
    # Using provider directly
    provider = Neo3Provider(network="mainnet")
    try:
        address = "NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp"
        balances = await provider.get_nep17_balances(address)
        print(f"NEP-17 balances: {balances}")
    finally:
        await provider.close()

asyncio.run(neo3_example())
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

#### 7. EVM Blockchain Tools Usage

```python
from spoon_toolkits.crypto.evm import EvmBalanceTool, EvmTransferTool, EvmSwapQuoteTool

# Get native token balance
balance_tool = EvmBalanceTool()
balance_result = await balance_tool.execute(
    rpc_url="https://eth-mainnet.g.alchemy.com/v2/your_key",
    address="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
)
print(f"ETH Balance: {balance_result}")

# Get ERC20 token balance
token_balance = await balance_tool.execute(
    rpc_url="https://eth-mainnet.g.alchemy.com/v2/your_key",
    address="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    token_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"  # USDC
)
print(f"USDC Balance: {token_balance}")

# Get swap quote
quote_tool = EvmSwapQuoteTool()
quote_result = await quote_tool.execute(
    chain_id=1,  # Ethereum mainnet
    from_token="0x0000000000000000000000000000000000000000",  # Native ETH
    to_token="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
    amount="1.0",
    aggregator="both"  # Compare Bebop and LiFi
)
print(f"Swap Quote: {quote_result}")
```

#### 8. Solana Blockchain Tools Usage

```python
from spoon_toolkits.crypto.solana import SolanaWalletInfoTool, SolanaTransferTool, SolanaSwapTool

# Get wallet information
wallet_tool = SolanaWalletInfoTool()
wallet_info = await wallet_tool.execute(
    rpc_url="https://api.mainnet-beta.solana.com",
    address="BJyWLDo4xYDs2bp2dK2BcMFBJuRxnUBcJkNqjxgg81hR",
    include_tokens=True
)
print(f"Wallet Balance: {wallet_info}")

# Transfer SOL
transfer_tool = SolanaTransferTool()
transfer_result = await transfer_tool.execute(
    rpc_url="https://api.devnet.solana.com",
    recipient="GMkCtcMmLTQ3jwxExRvSqCE5u4ypFYNa6TxVMZ9smuud",
    amount=0.5
)
print(f"Transfer Result: {transfer_result}")
```

#### 9. Memory Management Tools Usage

```python
from spoon_toolkits.memory import AddMemoryTool, SearchMemoryTool, GetAllMemoryTool

# Add memory
add_tool = AddMemoryTool()
add_result = await add_tool.execute(
    content="User prefers dark mode UI",
    user_id="user_123",
    metadata={"source": "preference_survey"}
)
print(f"Memory Added: {add_result}")

# Search memories
search_tool = SearchMemoryTool()
search_result = await search_tool.execute(
    query="What are the user's UI preferences?",
    user_id="user_123",
    limit=5
)
print(f"Search Results: {search_result}")

# Get all memories
get_all_tool = GetAllMemoryTool()
all_memories = await get_all_tool.execute(
    user_id="user_123",
    limit=50
)
print(f"All Memories: {all_memories}")
```

#### 10. ElevenLabs Audio Tools Usage

```python
from spoon_toolkits.audio import (
    ElevenLabsTextToSpeechTool,
    ElevenLabsSpeechToTextTool,
    ElevenLabsVoiceDesignTool,
    ElevenLabsInstantVoiceCloneTool,
)

# Text-to-Speech
tts_tool = ElevenLabsTextToSpeechTool()
tts_result = await tts_tool.execute(
    text="Hello, this is a demonstration of AI voice synthesis.",
    voice_id="JBFqnCBsd6RMkjVDRZzb",  # George voice
    model_id="eleven_multilingual_v2",
    save_to_file="output.mp3"
)
print(f"Generated audio: {tts_result.output['audio_size_bytes']} bytes")

# Speech-to-Text
stt_tool = ElevenLabsSpeechToTextTool()
stt_result = await stt_tool.execute(
    file_path="recording.mp3",
    language="en"  # Optional, auto-detected if not specified
)
print(f"Transcription: {stt_result.output['text']}")

# Voice Design
design_tool = ElevenLabsVoiceDesignTool()
design_result = await design_tool.execute(
    voice_description="A warm elderly British man with a gentle storytelling tone",
    auto_generate_text=True
)
print(f"Generated {design_result.output['preview_count']} voice previews")

# Voice Cloning
clone_tool = ElevenLabsInstantVoiceCloneTool()
clone_result = await clone_tool.execute(
    name="My Custom Voice",
    files=["sample1.mp3", "sample2.mp3"],
    description="Cloned from my recordings"
)
print(f"Cloned voice ID: {clone_result.output['voice_id']}")
```

## 🔧 Tool Features

### 📊 Data Richness

- Multi-chain data support
- Real-time price and market data
- Historical data analysis

### 🌐 Multi-chain Support

- Ethereum ecosystem
- Solana ecosystem
- Neo blockchain (classic and N3)
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
