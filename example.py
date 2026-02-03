"""
Example usage of the AI Honeypot System
This script demonstrates how to:
1. Generate an API key
2. Start a conversation with the honeypot
3. Retrieve session information
"""

from authentication.auth import create_api_key
from fastapi.testclient import TestClient
from main import app
import json


def main():
    print("=" * 60)
    print("AI HONEYPOT SYSTEM - EXAMPLE USAGE")
    print("=" * 60)
    
    # Create a test client
    client = TestClient(app)
    
    # Step 1: Generate API Key
    print("\n1. Generating API Key...")
    api_key, success = create_api_key("example-app")
    if success:
        print(f"   ✓ API Key: {api_key}")
        print("   ⚠️  Save this key securely - it won't be shown again!")
    else:
        print("   ✗ Failed to generate API key")
        return
    
    # Step 2: Send first message (scam detected)
    print("\n2. Sending first scam message...")
    response = client.post('/chat', 
        json={
            'sessionId': 'example-session-001',
            'message': {
                'sender': 'scammer',
                'text': 'Your bank account will be blocked today. Verify immediately by sharing your UPI ID.',
                'timestamp': 1770005528731
            },
            'conversationHistory': [],
            'metadata': {
                'channel': 'SMS',
                'language': 'English',
                'locale': 'IN'
            }
        },
        headers={'X-API-Key': api_key}
    )
    print(f"   Status: {response.status_code}")
    print(f"   AI Response: {response.json()['reply']}")
    
    # Step 3: Send follow-up message with data
    print("\n3. Sending follow-up message with UPI and phone...")
    response = client.post('/chat', 
        json={
            'sessionId': 'example-session-001',
            'message': {
                'sender': 'scammer',
                'text': 'Send to scammer123@paytm or call 9876543210 now!',
                'timestamp': 1770005538731
            },
            'conversationHistory': [
                {
                    'sender': 'scammer',
                    'text': 'Your bank account will be blocked today. Verify immediately by sharing your UPI ID.',
                    'timestamp': 1770005528731
                },
                {
                    'sender': 'user',
                    'text': 'Why will my account be blocked? I haven\'t done anything wrong.',
                    'timestamp': 1770005529731
                }
            ],
            'metadata': {
                'channel': 'SMS',
                'language': 'English',
                'locale': 'IN'
            }
        },
        headers={'X-API-Key': api_key}
    )
    print(f"   Status: {response.status_code}")
    print(f"   AI Response: {response.json()['reply']}")
    
    # Step 4: Retrieve session information
    print("\n4. Retrieving session information...")
    response = client.get('/sessions/example-session-001',
        headers={'X-API-Key': api_key}
    )
    print(f"   Status: {response.status_code}")
    print(f"   Session Info:")
    session_data = response.json()
    print(f"      - Is Scam: {session_data['is_scam']}")
    print(f"      - Message Count: {session_data['message_count']}")
    print(f"      - Extracted Data:")
    print(f"         • UPI IDs: {session_data['extracted_data']['upi_ids']}")
    print(f"         • Phone Numbers: {session_data['extracted_data']['phone_numbers']}")
    print(f"         • Bank Accounts: {session_data['extracted_data']['bank_accounts']}")
    print(f"         • Phishing Links: {session_data['extracted_data']['phishing_links']}")
    
    # Step 5: Get conversation history
    print("\n5. Retrieving conversation history...")
    response = client.get('/sessions/example-session-001/messages',
        headers={'X-API-Key': api_key}
    )
    print(f"   Status: {response.status_code}")
    messages = response.json()['messages']
    print(f"   Total Messages: {len(messages)}")
    for i, msg in enumerate(messages, 1):
        sender = "🔴 Scammer" if msg['sender'] == 'scammer' else "🟢 AI Agent"
        print(f"      {i}. {sender}: {msg['text']}")
    
    print("\n" + "=" * 60)
    print("✅ Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
