# Chainbase Tools

这个模块提供了一组基于Chainbase API的工具，用于与区块链网络交互。

## 环境设置

使用前需要设置Chainbase API密钥：

```bash
export CHAINBASE_API_KEY="your_api_key_here"
```

或者在代码中设置：

```python
import os
os.environ["CHAINBASE_API_KEY"] = "your_api_key_here"
```

## 可用工具

### 基础工具

- `GetLatestBlockNumberTool`: 获取区块链网络的最新区块高度
- `GetBlockByNumberTool`: 根据区块号获取区块详情
- `GetTransactionByHashTool`: 根据哈希获取交易详情
- `GetAccountTransactionsTool`: 获取指定地址的交易历史

### 账户工具

- `GetAccountBalanceTool`: 获取指定地址的原生代币余额
- `GetAccountTokensTool`: 获取指定地址的所有ERC20代币余额
- `GetAccountNFTsTool`: 获取指定地址拥有的NFT列表

### 合约工具

- `ContractCallTool`: 调用指定合约的函数
- `GetTokenMetadataTool`: 获取代币的元数据信息

## 使用示例

```python
from spoon_toolkits.chainbase import GetLatestBlockNumberTool, GetAccountBalanceTool

async def example():
    # 获取以太坊最新区块
    block_tool = GetLatestBlockNumberTool()
    block_result = await block_tool.execute(chain_id=1)
    print(f"最新区块: {block_result}")
    
    # 获取账户ETH余额
    balance_tool = GetAccountBalanceTool()
    balance_result = await balance_tool.execute(
        chain_id=1,
        address="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # vitalik.eth
    )
    print(f"账户余额: {balance_result}")

# 运行示例
import asyncio
asyncio.run(example())
```

## 支持的区块链网络

工具支持多个区块链网络，通过`chain_id`参数指定：

- Ethereum: 1
- Polygon: 137
- BSC: 56
- Avalanche: 43114
- Arbitrum One: 42161
- Optimism: 10
- Base: 8453
- zkSync: 324
- Merlin: 4200

## 服务器模式

可以通过以下方式启动FastMCP服务器：

```bash
python -m spoon_toolkits.chainbase
```

或在代码中：

```python
from spoon_toolkits.chainbase import mcp_server

if __name__ == "__main__":
    mcp_server.run(
        transport="sse",
        host="0.0.0.0",
        port=8000,
        path="/sse"
    )
``` 