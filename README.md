# AI Honeypot System

Autonomous AI system that detects scam messages and actively engages scammers to extract critical information like bank account details, UPI IDs, and phishing links.

## Features

- 🔍 **Hybrid Scam Detection**: Keyword-based + AI-powered detection with Gemini 2.0 Flash
- 🤖 **AI Agent**: Believable human-like persona that engages scammers
- 📊 **Data Extraction**: Automatic extraction using regex + AI (bank accounts, UPI IDs, phishing links, phone numbers)
- 🔒 **Secure Authentication**: API key authentication with SHA-256 hashing (stored outside database)
- 💾 **Optimized Database**: Batch writes for performance, SQLite with conversation history
- 🚦 **Rate Limiting**: Built-in Gemini API rate limiting (75% of free tier limits)
- 🛡️ **Security Guardrails**: Prevents prompt injection, jailbreaking, and AI disclosure
- 📞 **Callback System**: Sends extracted intelligence when scam is confirmed

## Architecture

```
├── main.py                          # FastAPI application with /message endpoint
├── authentication/
│   ├── auth.py                     # API key management (secure file storage)
│   └── generate_api_key.py         # Script to generate API keys
├── database/
│   ├── database.py                 # SQLite models and batch operations
│   └── schemas.py                  # Pydantic schemas for validation
└── modules/
    ├── agent.py                    # Gemini AI agent with guardrails
    ├── detector.py                 # Hybrid scam detection (keywords + AI)
    ├── extractor.py                # Data extraction (regex + AI)
    └── callback.py                 # (Reserved for future use)
```

## Quick Start

### 1. Installation

```bash
pip install -r requirements.txt
```

### 2. Environment Configuration

Create a `.env` file (copy from `.env.example`):

```env
# Required for AI features
GEMINI_API_KEY=your_gemini_api_key_here

# Optional configurations
GEMINI_MODEL=gemini-2.0-flash-exp
DATABASE_PATH=honeypot.db
SECRET_SALT=your_secret_salt_for_hashing
API_KEYS_FILE=.api_keys.json
CALLBACK_URL=https://your-callback-endpoint.com/scam-data
PORT=8000
```

**Important Security Notes:**
- Change `SECRET_SALT` to a random string in production
- Never commit `.env` or `.api_keys.json` to version control
- Set proper file permissions: `chmod 600 .api_keys.json`

### 3. Generate API Key

```bash
cd authentication
python generate_api_key.py my-application-name
```

**Save the generated API key securely - it won't be shown again!**

### 4. Start the Server

```bash
python main.py
# or
uvicorn main:app --reload --port 8000
```

## API Usage

### Message Endpoint (Only Public Endpoint)

**POST /message**

Send a message to the honeypot system. This is the only endpoint exposed for message processing.

**Headers:**
```
X-API-Key: your_api_key_here
Content-Type: application/json
```

**Request Body:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your account will be blocked. Verify immediately at bit.ly/scam123",
    "timestamp": 1738582028731
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "Previous message",
      "timestamp": 1738582000000
    },
    {
      "sender": "user",
      "text": "AI's previous response",
      "timestamp": 1738582001000
    }
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "oh no why is it blocked? i didnt do anything wrong. what link should i click?"
}
```

### How It Works

1. **Authentication**: API key verified from `X-API-Key` header
2. **Scam Detection**: 
   - First, keyword-based detection (fast)
   - If keywords match (confidence ≥ 30%), AI detection is invoked
   - Hybrid confidence score calculated (40% keywords + 60% AI)
3. **Data Extraction**:
   - Regex patterns extract UPI IDs, bank accounts, URLs, phone numbers
   - AI extraction runs in parallel for obfuscated data
   - Results merged and deduplicated
4. **AI Response Generation**:
   - Rate limiting checked (75% of Gemini free tier)
   - Context-aware response with human-like persona
   - Guardrails prevent AI disclosure and prompt injection
5. **Callback Trigger**:
   - Sent when: scam confirmed, confidence ≥ 60%, ≥3 exchanges, data extracted
   - Payload includes all extracted intelligence

### Callback Format

When scam is confirmed and intelligence is extracted, a callback is sent to `CALLBACK_URL`:

```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 18,
  "extractedIntelligence": {
    "bankAccounts": ["1234567890123"],
    "upiIds": ["scammer@paytm"],
    "phishingLinks": ["http://bit.ly/scam123"],
    "phoneNumbers": ["+919876543210"],
    "suspiciousKeywords": ["urgent", "verify", "account blocked", "click link"]
  },
  "agentNotes": "Engagement completed after 18 messages. Scam intelligence extracted."
}
```

## Security Features

### API Key Storage
- **NOT stored in database** (per security requirement)
- Stored in `.api_keys.json` with restricted permissions (600)
- SHA-256 hashed with secret salt
- File locking prevents concurrent access issues

### Input Sanitization
- Session ID validation (alphanumeric, hyphens, underscores only)
- Message length limits (max 2000 characters)
- Pydantic validation for all API requests

### AI Guardrails
- System prompt prevents AI disclosure
- Response validation filters prohibited content
- 20-message conversation limit
- Rate limiting prevents abuse
- Fallback responses when AI unavailable

### Prompt Injection Prevention
- Strict system prompt that can't be overridden
- Response validation
- Conversation length limits
- No user-controlled system messages

## Rate Limiting

Gemini 2.0 Flash Free Tier limits (75% safety margin):
- **11 requests per minute** (75% of 15 RPM)
- **1,125 requests per day** (75% of 1,500 RPD)

When limit reached, system falls back to template responses.

## Database Schema

The system uses SQLite with optimized batch operations:

- **sessions**: Conversation sessions with scam confidence and callback status
- **messages**: All messages in conversations
- **extracted_data**: Extracted scam information (deduplicated)
- **suspicious_keywords**: Matched keywords for pattern analysis

Database file: `honeypot.db` (auto-generated, excluded from git)

## Performance Optimizations

1. **Batch Database Writes**: Multiple inserts in single transaction
2. **Conditional AI Invocation**: AI only called when keywords suggest scam
3. **Rate Limiting**: Prevents excessive API costs
4. **Connection Pooling**: Efficient database access
5. **Indexed Queries**: Fast lookups on session_id

## Development

### Manual Testing

Test scam detection:
```python
from modules.detector import detect_scam_hybrid

is_scam, confidence, keywords = detect_scam_hybrid(
    "Your account is blocked! Share UPI ID to verify immediately.",
    use_ai=True
)
print(f"Scam: {is_scam}, Confidence: {confidence:.2f}")
```

Test data extraction:
```python
from modules.extractor import DataExtractor

extractor = DataExtractor()
data = extractor.extract_from_text(
    "Send payment to 9876543210 or UPI: scammer@paytm",
    use_ai=True
)
print(f"Extracted: {data.to_dict()}")
```

### Generate Additional API Keys

```bash
cd authentication
python generate_api_key.py client-app-name
```

### Revoke API Key

```python
from authentication.auth import revoke_api_key

success = revoke_api_key("your_api_key_to_revoke")
```

## Edge Cases & Limitations

See comments in source files for edge cases:
- `auth.py`: Concurrent file access, corrupted API keys file
- `database.py`: Database locking, corruption, disk space
- `agent.py`: API timeouts, rate limits, prompt injection
- `detector.py`: API failures, ambiguous messages
- `extractor.py`: Malformed data, Unicode handling

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `GEMINI_API_KEY` | Google Gemini API key | None | Yes (for AI features) |
| `GEMINI_MODEL` | Gemini model name | `gemini-2.0-flash-exp` | No |
| `DATABASE_PATH` | SQLite database path | `honeypot.db` | No |
| `SECRET_SALT` | Salt for API key hashing | `default_salt...` | **Yes (change!)** |
| `API_KEYS_FILE` | API keys storage file | `.api_keys.json` | No |
| `CALLBACK_URL` | URL for scam intelligence | None | No |
| `PORT` | Server port | `8000` | No |

## Production Deployment

1. **Set strong `SECRET_SALT`**: Generate random string
2. **Secure API keys file**: `chmod 600 .api_keys.json`
3. **Use HTTPS**: Protect API keys in transit
4. **Set `CALLBACK_URL`**: Configure callback endpoint
5. **Monitor rate limits**: Track Gemini API usage
6. **Database backups**: Regular backups of `honeypot.db`
7. **Log monitoring**: Track errors and performance

## License

Built for HCL GUVI AI Buildathon 2026

## Support

For issues or questions, refer to the source code comments and edge case documentation in each module.
