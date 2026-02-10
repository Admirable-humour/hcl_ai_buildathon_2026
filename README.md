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
├── main.py                          # FastAPI application with /message endpoint and also handles callback output to the URL mentioned as the environment variable.
├── authentication/
│   ├── auth.py                     # API key management (secure storage as JSON inside env variable.)
│   └── generate_api_key.py         # Script to generate API keys
├── database/
│   ├── database.py                 # SQLite models and batch operations
│   └── schemas.py                  # Pydantic schemas for validation
└── modules/
    ├── agent.py                    # Gemini AI agent with guardrails
    ├── detector.py                 # Hybrid scam detection (keywords + AI)
    └── extractor.py                # Data extraction (regex + AI)
```

**This project was vibecoded using GitHub Copilot and manually reviewed. The author of this project and the collaborators do not take any responsibility of any data loss or leaks, if it occurs through the use of this application.**

## API Usage

### Message Endpoint (Only Public Endpoint)

**POST /message**

Send a message to the honeypot system. This is the only endpoint exposed for message processing.

**Headers:**
```
X-API-Key: your_api_key_here
Content-Type: application/json
```

**Request Body (example here given for testing purposes):**
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

**Response (example response which you should get):**
```json
{
  "status": "success",
  "reply": "oh no why is it blocked? i didnt do anything wrong. what link should i click?"
}
```

### How It Works

1. **Authentication**: API key verified from `X-API-Key` header.
2. **Scam Detection**: 
   - First, keyword-based detection (fast)
   - If keywords match, AI detection is invoked
   - Hybrid confidence score calculated using keywords and AI based detection.
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

When scam is confirmed and intelligence is extracted, a callback like this is sent to `CALLBACK_URL`:

```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 18,
  "extractedIntelligence": {
    "bankAccounts": ["1234567890123"],
    "upiIds": ["scammer@paytm"],
    "phishingLinks": ["http://bit.ly/scam123"],
    "phoneNumbers": ["+911234567890"],
    "suspiciousKeywords": ["urgent", "verify", "account blocked", "click link"]
  },
  "agentNotes": "Engagement completed after 18 messages. Scam intelligence extracted."
}
```
### Set your own environment variables according to the the example environment file in the repository. A working render.yaml file has also been provided for auto deployment to Render as a web service. 


Built for HCL GUVI AI Buildathon 2026 
