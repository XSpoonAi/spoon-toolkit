# Desearch AI Integration for Spoon Framework

A powerful search and verification toolkit for the Spoon framework that provides real-time access to verified data across multiple platforms using the official Desearch SDK.

## 🎯 What It Does

This module enables Spoon AI agents to search and verify information across:
- **Social Media**: X (Twitter), Reddit
- **Academic Sources**: ArXiv, Wikipedia  
- **Video Platforms**: YouTube
- **Web Search**: Real-time web search
- **News Sources**: Real-time news aggregation

Instead of relying on potentially outdated or hallucinated data, your AI agents can now access current, verified information from multiple sources simultaneously.

## 🚀 Quick Start for Spoon Developers

### Prerequisites

Get your API key from [Desearch Console](https://console.desearch.ai/api-keys).

### Installation

1. **Install dependencies**:
```bash
pip install desearch-py>=1.0.0
pip install fastmcp>=0.1.0
pip install python-dotenv>=1.0.0
```

2. **Set up environment**:
```bash
# Create .env file
echo "DESEARCH_API_KEY=your_actual_api_key_here" > .env
```

3. **Test the integration**:
```bash
python test_integration.py
```

## 🔧 Integration with Spoon Framework

### Method 1: Using MCP Server (Recommended)

The easiest way to use Desearch in your Spoon AI agents:

```python
from spoon_toolkits.desearch import mcp_server

# The MCP server is automatically configured with all tools
# Spoon framework will handle the tool registration

# In your Spoon agent configuration:
agent_config = {
    "tools": [mcp_server],  # Add the Desearch MCP server
    # ... other agent configuration
}
```

### Method 2: Direct Function Usage

For direct integration in your custom Spoon tools:

```python
from spoon_toolkits.desearch import (
    search_ai_data,
    search_web,
    search_twitter_posts,
    search_social_media,
    search_academic
)

# Use in your custom Spoon tool
async def my_custom_search_tool(query: str):
    # Multi-platform AI search
    ai_results = await search_ai_data(
        query=query,
        platforms="web,reddit,wikipedia",
        limit=10
    )
    
    # Web search
    web_results = await search_web(
        query=query,
        num_results=5
    )
    
    return {
        "ai_results": ai_results,
        "web_results": web_results
    }
```

## 📚 Available Tools

### AI Search Tools

#### `search_ai_data(query, platforms, limit)`
Multi-platform AI-powered search across multiple sources.

**Parameters:**
- `query` (str): Search query
- `platforms` (str): Comma-separated platforms (web, reddit, wikipedia, youtube, twitter, arxiv)
- `limit` (int): Number of results per platform (minimum 10)

**Spoon Integration Example:**
```python
from spoon_toolkits.desearch import search_ai_data

# In your Spoon agent
async def research_trends(topic: str):
    result = await search_ai_data(
        query=f"{topic} trends 2024",
        platforms="web,reddit,wikipedia",
        limit=10
    )
    
    # Process results for your agent
    insights = []
    for platform, data in result['results'].items():
        for item in data['results'][:3]:  # Top 3 from each platform
            insights.append(f"{platform}: {item.get('title', item.get('text', 'No title'))}")
    
    return f"Found {result['total_results']} results across {len(result['platforms'])} platforms:\n" + "\n".join(insights)
```

#### `search_social_media(query, platform, limit)`
Search specific social media platforms.

**Parameters:**
- `query` (str): Search query
- `platform` (str): Platform (twitter, reddit)
- `limit` (int): Number of results (minimum 10)

**Spoon Integration Example:**
```python
from spoon_toolkits.desearch import search_social_media

# In your Spoon agent
async def monitor_social_sentiment(topic: str):
    twitter_results = await search_social_media(
        query=topic,
        platform="twitter",
        limit=10
    )
    
    # Analyze sentiment from social media
    tweets = twitter_results['results']
    return f"Found {len(tweets)} recent tweets about {topic}"
```

#### `search_academic(query, platform, limit)`
Search academic platforms for research papers.

**Parameters:**
- `query` (str): Search query
- `platform` (str): Platform (arxiv, wikipedia)
- `limit` (int): Number of results (minimum 10)

**Spoon Integration Example:**
```python
from spoon_toolkits.desearch import search_academic

# In your Spoon agent
async def research_papers(topic: str):
    papers = await search_academic(
        query=topic,
        platform="arxiv",
        limit=10
    )
    
    # Summarize research findings
    return f"Found {len(papers['results'])} research papers on {topic}"
```

### Web Search Tools

#### `search_web(query, num_results, start)`
Basic web search functionality.

**Parameters:**
- `query` (str): Search query
- `num_results` (int): Number of results (default 10)
- `start` (int): Starting position for pagination (default 0)

**Spoon Integration Example:**
```python
from spoon_toolkits.desearch import search_web

# In your Spoon agent
async def verify_information(claim: str):
    results = await search_web(
        query=claim,
        num_results=5
    )
    
    # Verify the claim against web sources
    sources = [item['title'] for item in results['results']]
    return f"Verified against {len(sources)} web sources: {', '.join(sources)}"
```

#### `search_twitter_posts(query, limit, sort)`
Search Twitter posts with various filters.

**Parameters:**
- `query` (str): Search query
- `limit` (int): Number of results (minimum 10)
- `sort` (str): Sort order (Top, Latest, etc.)

**Spoon Integration Example:**
```python
from spoon_toolkits.desearch import search_twitter_posts

# In your Spoon agent
async def get_latest_news(topic: str):
    tweets = await search_twitter_posts(
        query=topic,
        limit=10,
        sort="Latest"
    )
    
    # Extract latest news from tweets
    news_items = [tweet['text'][:100] for tweet in tweets['results'][:5]]
    return f"Latest news on {topic}:\n" + "\n".join(news_items)
```

#### `search_twitter_links(query, limit)`
Search for links shared on Twitter.

**Parameters:**
- `query` (str): Search query
- `limit` (int): Number of results (minimum 10)

**Spoon Integration Example:**
```python
from spoon_toolkits.desearch import search_twitter_links

# In your Spoon agent
async def find_viral_links(topic: str):
    links = await search_twitter_links(
        query=topic,
        limit=10
    )
    
    # Find viral content
    viral_links = [link['url'] for link in links['results']]
    return f"Found {len(viral_links)} viral links about {topic}"
```

## 🎯 Real-World Spoon Use Cases

### 1. AI Agent Research Assistant
```python
# In your Spoon agent
async def research_assistant(query: str):
    # Get comprehensive research from multiple sources
    ai_results = await search_ai_data(query, "web,reddit,wikipedia", 10)
    social_results = await search_social_media(query, "twitter", 5)
    academic_results = await search_academic(query, "arxiv", 5)
    
    return {
        "comprehensive_research": ai_results,
        "social_insights": social_results,
        "academic_papers": academic_results
    }
```

### 2. News Verification Agent
```python
# In your Spoon agent
async def verify_news(claim: str):
    # Cross-verify information across multiple sources
    web_results = await search_web(claim, 5)
    twitter_results = await search_twitter_posts(claim, 5)
    
    # Analyze credibility
    credibility_score = len(web_results['results']) + len(twitter_results['results'])
    return f"Credibility score: {credibility_score}/10"
```

### 3. Market Intelligence Agent
```python
# In your Spoon agent
async def market_intelligence(company: str):
    # Gather market intelligence from multiple sources
    news = await search_web(f"{company} news", 5)
    social_sentiment = await search_social_media(company, "twitter", 10)
    reddit_discussion = await search_social_media(company, "reddit", 5)
    
    return {
        "news": news,
        "social_sentiment": social_sentiment,
        "community_discussion": reddit_discussion
    }
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file:

```bash
# Required
DESEARCH_API_KEY=your_actual_api_key_here

# Optional (defaults shown)
DESEARCH_BASE_URL=https://api.desearch.ai
DESEARCH_TIMEOUT=30
```

## 🧪 Testing

### Run Integration Tests
```bash
python test_integration.py
```

### Run Examples
```bash
python example.py
```

Expected output:
```
🚀 Desearch AI Integration Examples
✅ All examples completed successfully!
🎉 Desearch AI integration is working correctly!
```

## 📁 Module Structure

```
desearch/
├── __init__.py                    # Main module entry point
├── ai_search_official.py          # AI search tools (official SDK)
├── web_search_official.py         # Web search tools (official SDK)
├── env.py                         # Environment configuration
├── cache.py                       # Caching utilities
├── requirements.txt               # Dependencies
├── README.md                      # This file
├── example.py                     # Usage examples
└── test_integration.py           # Integration tests
```

## ⚠️ Troubleshooting

### Common Issues

**1. API Key Error**
```
Error: API key ID missing or invalid format
```
**Solution**: Check your `.env` file and ensure `DESEARCH_API_KEY` is set correctly.

**2. Import Errors**
```
ModuleNotFoundError: No module named 'desearch_py'
```
**Solution**: Install the official SDK: `pip install desearch-py`

**3. Count Parameter Error**
```
Input should be greater than or equal to 10
```
**Solution**: Ensure `limit` parameter is at least 10 for all search functions.

**4. Environment Variables Not Loading**
```
API key is missing
```
**Solution**: Ensure `.env` file is in the correct location and properly formatted.

### Performance Tips

1. **Use Caching**: Results are automatically cached for 5 minutes
2. **Batch Requests**: Combine multiple platforms in one `search_ai_data` call
3. **Limit Results**: Use appropriate `limit` values to avoid rate limits
4. **Error Handling**: Always check for `"error"` keys in responses

## 📊 Features

- ✅ **Multi-platform Search**: Web, Reddit, Wikipedia, YouTube, Twitter, ArXiv
- ✅ **Real-time Data**: Access current information from multiple sources
- ✅ **AI-powered**: Uses Desearch's AI to enhance search results
- ✅ **Caching**: Automatic result caching for better performance
- ✅ **MCP Integration**: Seamless integration with Spoon framework
- ✅ **Error Handling**: Robust error handling and validation
- ✅ **Async Support**: Full async/await support for non-blocking operations

## 🎯 Key Benefits for Spoon Developers

1. **Solve AI Hallucination**: Get real-time, verified data instead of potentially outdated information
2. **Multi-source Validation**: Cross-validate information across multiple platforms
3. **Easy Integration**: Simple API that works seamlessly with Spoon framework
4. **Performance Optimized**: Caching and efficient request handling
5. **Production Ready**: Tested and validated with real API calls

## 📞 Support

- **Documentation**: [Desearch API Docs](https://docs.desearch.ai)
- **API Keys**: [Desearch Console](https://console.desearch.ai/api-keys)
- **Issues**: Report bugs in the project repository

## 📄 License

This module is part of the Spoon framework and follows the same licensing terms. 