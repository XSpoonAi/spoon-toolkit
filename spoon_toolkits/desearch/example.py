"""
Desearch AI Integration - Usage Examples for Spoon Developers

This file demonstrates how to use the Desearch AI integration module in Spoon framework.
"""

import asyncio
import sys

# Add current directory to path for imports
sys.path.append('.')

async def example_spoon_mcp_integration():
    """Example: MCP server integration for Spoon agents"""
    print("🔍 Example: MCP Server Integration for Spoon Agents")
    print("=" * 60)
    
    try:
        # Import the MCP server for Spoon integration
        from __init__ import mcp_server
        
        print("✅ MCP server created successfully")
        print(f"Server name: {mcp_server.name}")
        print("✅ Ready for Spoon framework integration")
        print("\n📋 Usage in Spoon agent configuration:")
        print("agent_config = {")
        print("    'tools': [mcp_server],  # Add Desearch MCP server")
        print("    # ... other agent configuration")
        print("}")
        
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

async def example_spoon_direct_functions():
    """Example: Direct function usage in Spoon tools"""
    print("\n🔍 Example: Direct Function Usage in Spoon Tools")
    print("=" * 60)
    
    try:
        # Import functions for direct use in Spoon tools
        from __init__ import (
            search_ai_data,
            search_web,
            search_twitter_posts,
            search_social_media,
            search_academic
        )
        
        print("✅ All functions imported successfully")
        print("📋 Available functions:")
        print("  - search_ai_data()")
        print("  - search_web()")
        print("  - search_twitter_posts()")
        print("  - search_social_media()")
        print("  - search_academic()")
        
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

async def example_research_assistant():
    """Example: AI Research Assistant for Spoon agents"""
    print("\n🔍 Example: AI Research Assistant")
    print("=" * 60)
    
    try:
        # Use the implementation functions directly
        from ai_search_official import _search_ai_data_impl, _search_social_media_impl, _search_academic_impl
        
        # Simulate a research assistant agent
        query = "artificial intelligence trends 2024"
        
        print(f"🔍 Researching: {query}")
        
        # Get comprehensive research from multiple sources
        ai_results = await _search_ai_data_impl(query, "web,reddit,wikipedia", 10)
        social_results = await _search_social_media_impl(query, "twitter", 5)
        academic_results = await _search_academic_impl(query, "arxiv", 5)
        
        print(f"✅ AI Search: {ai_results.get('total_results', 0)} results")
        print(f"✅ Social Media: {len(social_results.get('results', []))} tweets")
        print(f"✅ Academic: {len(academic_results.get('results', []))} papers")
        
        # Process results for agent response
        insights = []
        for platform, data in ai_results.get('results', {}).items():
            results_list = data.get('results', [])
            if isinstance(results_list, list):
                for item in results_list[:2]:  # Top 2 from each platform
                    if isinstance(item, dict):
                        title = item.get('title', item.get('text', 'No title'))[:60]
                        insights.append(f"  - {platform}: {title}...")
        
        print("\n📊 Key Insights:")
        for insight in insights[:6]:  # Show top 6 insights
            print(insight)
        
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

async def example_news_verification():
    """Example: News Verification Agent for Spoon"""
    print("\n🔍 Example: News Verification Agent")
    print("=" * 60)
    
    try:
        # Use the implementation functions directly
        from web_search_official import _search_web_impl, _search_twitter_posts_impl
        
        # Simulate verifying a news claim
        claim = "blockchain technology adoption 2024"
        
        print(f"🔍 Verifying claim: {claim}")
        
        # Cross-verify information across multiple sources
        web_results = await _search_web_impl(claim, 5, 0)
        twitter_results = await _search_twitter_posts_impl(claim, 5, "Top")
        
        # Analyze credibility
        web_sources = len(web_results.get('results', []))
        twitter_sources = len(twitter_results.get('results', []))
        credibility_score = min(10, web_sources + twitter_sources)
        
        print(f"✅ Web sources: {web_sources}")
        print(f"✅ Twitter sources: {twitter_sources}")
        print(f"📊 Credibility score: {credibility_score}/10")
        
        if credibility_score >= 7:
            print("✅ Claim appears credible")
        elif credibility_score >= 4:
            print("⚠️ Claim needs more verification")
        else:
            print("❌ Claim lacks credible sources")
        
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

async def example_market_intelligence():
    """Example: Market Intelligence Agent for Spoon"""
    print("\n🔍 Example: Market Intelligence Agent")
    print("=" * 60)
    
    try:
        # Use the implementation functions directly
        from web_search_official import _search_web_impl
        from ai_search_official import _search_social_media_impl
        
        # Simulate market intelligence gathering
        company = "Tesla"
        
        print(f"🔍 Gathering market intelligence for: {company}")
        
        # Gather market intelligence from multiple sources
        news = await _search_web_impl(f"{company} news", 5, 0)
        social_sentiment = await _search_social_media_impl(company, "twitter", 10)
        reddit_discussion = await _search_social_media_impl(company, "reddit", 5)
        
        print(f"✅ News articles: {len(news.get('results', []))}")
        print(f"✅ Social media mentions: {len(social_sentiment.get('results', []))}")
        print(f"✅ Reddit discussions: {len(reddit_discussion.get('results', []))}")
        
        # Summarize market intelligence
        total_sources = len(news.get('results', [])) + len(social_sentiment.get('results', [])) + len(reddit_discussion.get('results', []))
        print(f"📊 Total market intelligence sources: {total_sources}")
        
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

async def main():
    """Run all Spoon developer examples"""
    print("🚀 Desearch AI Integration - Spoon Developer Examples")
    print("=" * 70)
    print()
    
    examples = [
        ("MCP Integration", example_spoon_mcp_integration),
        ("Direct Functions", example_spoon_direct_functions),
        ("Research Assistant", example_research_assistant),
        ("News Verification", example_news_verification),
        ("Market Intelligence", example_market_intelligence),
    ]
    
    passed = 0
    total = len(examples)
    
    for name, example_func in examples:
        print(f"Running: {name}")
        if await example_func():
            passed += 1
        print()
    
    print(f"📊 Example Results: {passed}/{total} examples successful")
    
    if passed == total:
        print("✅ All examples completed successfully!")
        print("🎉 Desearch AI integration is ready for Spoon developers!")
        print("\n💡 Next Steps:")
        print("1. Add mcp_server to your Spoon agent configuration")
        print("2. Use the provided functions in your custom Spoon tools")
        print("3. Implement real-world use cases like research assistants")
    else:
        print("❌ Some examples failed. Please check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    asyncio.run(main()) 