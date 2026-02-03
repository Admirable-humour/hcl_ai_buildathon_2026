# AI Honeypot System

Autonomous AI system that detects scam messages and actively engages scammers to extract critical information like bank account details, UPI IDs, and phishing links.

## Features

- 🔍 **Scam Detection**: Keyword-based detection with confidence scoring
- 🤖 **AI Agent**: Gemini-powered conversational agent with believable persona
- 📊 **Data Extraction**: Automatic extraction of bank accounts, UPI IDs, phishing links
- 🔒 **Secure API**: API key authentication with SHA-256 hashing
- 💾 **SQLite Database**: Stores conversations and extracted data
- 📝 **Type-Safe**: Pydantic schemas with strict validation

## Quick Start

### 1. Installation

```bash
pip install -r requirements.txt
```

### 2. Environment Variables

Create a `.env` file:

```env
# Required for Gemini AI (optional - uses fallback responses if not set)
GEMINI_API_KEY=your_gemini_api_key_here

# Optional configurations
GEMINI_MODEL=gemini-2.0-flash-exp
DATABASE_PATH=honeypot.db
SECRET_SALT=your_secret_salt_for_hashing
PORT=8000
```

### 3. Generate API Key

```python
from authentication.auth import create_api_key

api_key, success = create_api_key("my-app")
print(f"API Key: {api_key}")
# Save this key securely - it won't be shown again!
```

### 4. Start the Server

```bash
python main.py
# or
uvicorn main:app --reload --port 8000
```

## API Usage

### Chat Endpoint

**POST /chat**

Send a message to the honeypot system.

```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key_here" \
  -d '{
    "sessionId": "unique-session-id",
    "message": {
      "sender": "scammer",
      "text": "Your account will be blocked. Verify immediately.",
      "timestamp": 1770005528731
    },
    "conversationHistory": [],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```

**Response:**

```json
{
  "status": "success",
  "reply": "Why will my account be blocked? I haven't done anything wrong."
}
```

### Get Session Info

**GET /sessions/{session_id}**

```bash
curl http://localhost:8000/sessions/unique-session-id \
  -H "X-API-Key: your_api_key_here"
```

**Response:**

```json
{
  "sessionId": "unique-session-id",
  "is_scam": true,
  "message_count": 2,
  "created_at": "2026-02-03T09:30:00",
  "last_activity": "2026-02-03T09:35:00",
  "extracted_data": {
    "bank_accounts": ["1234567890"],
    "upi_ids": ["scammer@paytm"],
    "phishing_links": ["http://bit.ly/scam"],
    "phone_numbers": ["9999888877"]
  }
}
```

### Get Conversation History

**GET /sessions/{session_id}/messages**

```bash
curl http://localhost:8000/sessions/unique-session-id/messages \
  -H "X-API-Key: your_api_key_here"
```

## Architecture

```
├── main.py              # FastAPI application and endpoints
├── authentication/
│   └── auth.py         # API key generation and verification
├── database/
│   ├── database.py     # SQLite models and operations
│   └── schemas.py      # Pydantic schemas for validation
└── modules/
    ├── agent.py        # Gemini AI conversational agent
    ├── detector.py     # Scam detection logic
    ├── extractor.py    # Data extraction (UPI, bank accounts, links)
    └── callback.py     # (Reserved for future use)
```

## Security Features

- **API Key Authentication**: SHA-256 hashed keys with secret salt
- **Input Sanitization**: Prevents injection attacks
- **Session Validation**: Strict session ID format validation
- **Database Security**: Parameterized queries to prevent SQL injection
- **Type Safety**: Pydantic validation for all API requests

## Database Schema

The system uses SQLite with four main tables:

- **sessions**: Conversation sessions with metadata
- **messages**: All messages in conversations
- **extracted_data**: Extracted scam information
- **api_keys**: Authentication credentials

Database file: `honeypot.db` (auto-generated, excluded from git)

## Development

### Run Tests

```python
# Basic functionality test
python -c "
from modules.detector import detect_scam
is_scam, confidence, _ = detect_scam('Account blocked! Share UPI now.')
print(f'Scam detected: {is_scam}, Confidence: {confidence:.2f}')
"
```

### Test with FastAPI TestClient

```python
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)
response = client.get("/health")
print(response.json())
```

## Environment Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key | None (uses fallback) |
| `GEMINI_MODEL` | Gemini model name | `gemini-2.0-flash-exp` |
| `DATABASE_PATH` | SQLite database path | `honeypot.db` |
| `SECRET_SALT` | Salt for API key hashing | `default_salt_change_in_production` |
| `PORT` | Server port | `8000` |

## License

Built for HCL GUVI AI Buildathon 2026

