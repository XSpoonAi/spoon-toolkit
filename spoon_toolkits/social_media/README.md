# Social Media Tools for SpoonAI

This is a social media toolkit designed for SpoonAI, providing integration with Discord, Twitter, Telegram, and Email.

## 📁 Module Overview

### 🎮 Discord Tools (`discord_tool.py`)

- **Interactive Bot**: Support real-time conversations in Discord servers.
- **Sending Message**: Send messages to specified channels.
- **Command Handling**: Support custom commands and mention responses.
- **Agent Integration**: Integrate with SpoonAI Agent for intelligent conversations.

### 🐦 Twitter Tools (`twitter_tool.py`)

- **Post Tweets**: Publish new tweets.
- **Reply to Tweets**: Reply to specified tweets.
- **Like Functionality**: Like tweets.
- **Timeline Reading**: Read user timelines.
- **Notification Sending**: Support tagged notification tweets.

### 📱 Telegram Tools (`telegram_tool.py`)

- **Bot Functionality**: Run Telegram bots.
- **Message Sending**: Send messages to specified chats.
- **Interaction Handling**: Process user messages and respond.
- **Agent Integration**: Support integration with SpoonAI Agent.

### 📧 Email Tools (`email_tool.py`)

- **Email Sending**: Send HTML or plain text emails.
- **Bulk Sending**: Support for multiple recipients.
- **Template Support**: Automatic HTML formatting.
- **SMTP Configuration**: Flexible SMTP server configuration.

## 🚀 Quick Start

### Environment Variable Configuration

```bash
# Discord Configuration
export DISCORD_BOT_TOKEN="your_discord_bot_token"
export DISCORD_DEFAULT_CHANNEL_ID="your_default_channel_id"

# Twitter Configuration
export TWITTER_CONSUMER_KEY="your_consumer_key"
export TWITTER_CONSUMER_SECRET="your_consumer_secret"
export TWITTER_ACCESS_TOKEN="your_access_token"
export TWITTER_ACCESS_TOKEN_SECRET="your_access_token_secret"
export TWITTER_USER_ID="your_user_id"
export TWITTER_BEARER_TOKEN="your_bearer_token"  # Optional

# Telegram Configuration
export TELEGRAM_BOT_TOKEN="your_telegram_bot_token"
export TELEGRAM_DEFAULT_CHAT_ID="your_default_chat_id"

# Email Configuration
export EMAIL_SMTP_SERVER="smtp.gmail.com"
export EMAIL_SMTP_PORT="587"
export EMAIL_SMTP_USER="your_email@gmail.com"
export EMAIL_SMTP_PASSWORD="your_app_password"
export EMAIL_FROM="your_email@gmail.com"
export EMAIL_DEFAULT_RECIPIENTS="recipient1@example.com,recipient2@example.com"
```

### Use Cases

#### 1. Send Message on Discord

```python
from social_media import DiscordTool

# Create Discord tool instance
discord_tool = DiscordTool()

# Send message
success = await discord_tool.send_message(
    message="Hello from SpoonAI!",
    channel_id="123456789"  # Optional, uses default channel if not specified
)

# Start bot (for interactive features)
# await discord_tool.start_bot()
```

#### 2. Post on Twitter

```python
from social_media import TwitterTool

# Create Twitter tool instance
twitter_tool = TwitterTool()

# Post tweet
result = twitter_tool.post_tweet("Hello Twitter from SpoonAI! #AI #Blockchain")

# Reply to tweet
reply_result = twitter_tool.reply_to_tweet(
    tweet_id="1234567890",
    message="Thanks for the mention!"
)

# Like tweet
like_result = twitter_tool.like_tweet("1234567890")
```

#### 3. Send Message on Telegram

```python
from social_media import TelegramTool

# Create Telegram tool instance
telegram_tool = TelegramTool()

# 发送消息
success = await telegram_tool.send_message(
    message="Hello from SpoonAI!",
    chat_id="123456789"  # Optional, uses default chat if not specified
)

# Start bot
# await telegram_tool.start_bot()
```

#### 4. Send Email

```python
from social_media import EmailTool

# Create Email tool instance
email_tool = EmailTool()

# Send email
success = await email_tool.send_message(
    message="This is a test email from SpoonAI",
    to_emails=["user@example.com"],
    subject="SpoonAI Notification",
    html_format=True
)
```

#### 5. Using Convenience Functions

```python
from social_media.discord_tool import send_discord_message
from social_media.twitter_tool import post_tweet
from social_media.telegram_tool import send_telegram_message
from social_media.email_tool import send_email

# Use functions directly
discord_result = await send_discord_message("Hello Discord!")
twitter_result = await post_tweet("Hello Twitter!")
telegram_result = await send_telegram_message("Hello Telegram!")
email_result = await send_email("Hello Email!", ["user@example.com"])
```

## 🔧 Tool Features

### 🛡️ Error Handling

- Comprehensive exception handling mechanism
- Detailed logging
- Configuration validation functionality

### 📊 Unified Interface

- All tools inherit from a base class
- Unified request/response model
- Consistent API design

### 🔄 Asynchronous Support

- Full support for asynchronous operations
- Non-blocking message sending
- Efficient concurrent processing

### 🌐 Agent Integration

- Support integration with SpoonAI Agent
- Intelligent conversation handling
- Automatic message routing

## 📖 API Documentation

### Base Classes

#### `SocialMediaToolBase`

Base abstract class for all social media tools.

#### `NotificationToolBase`

Base class for notification tools, inherits from `SocialMediaToolBase`.

#### `InteractiveToolBase`

Base class for interactive tools (e.g., bots), inherits from `SocialMediaToolBase`。

### Request/Response Models

#### `MessageRequest`

```python
class MessageRequest(BaseModel):
    message: str  # Content
```

#### `MessageResponse`

```python
class MessageResponse(BaseModel):
    success: bool  # Whether the operation was successful
    message: str   # Response message or error description
    data: Optional[Dict[str, Any]]  # Additional response data
```

## 🔒 Security Notes

1. **API Key Security**: Ensure all API keys and tokens are securely stored and not committed to version control.
2. **Permission Control**: Configure appropriate permissions for bots to avoid over-authorization.
3. **Rate Limits**: Be mindful of each platform’s API rate limits to avoid restrictions.
4. **Data Validation**: All input data is validated to ensure security.

## 🤝 Contribution

1. Fork the project.
2. Create a feature branch.
3. Commit changes.
4. Create a Pull Request.

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

## 🆘 Support

For issues or suggestions, please submit an Issue or contact the development team.

---

**Note**: Ensure that relevant API keys and environment variables are correctly configured before using these tools. Some features may require paid API services.
