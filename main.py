"""
FastAPI main application for AI Honeypot System

Edge Cases to Handle:
- Invalid/malformed requests - handled by Pydantic validation
- Concurrent requests to same session - database handles with transactions
- Missing environment variables - graceful degradation with fallbacks
"""
from fastapi import FastAPI, HTTPException, Header, Depends
from contextlib import asynccontextmanager
from typing import Optional, AsyncGenerator
import os
import asyncio
import httpx

# Import modules
from database.schemas import MessageRequest, MessageResponse
from database.database import (
    SessionManager, MessageManager, ExtractedDataManager, 
    SuspiciousKeywordManager, init_database
)
from authentication.auth import verify_api_key, validate_session_id, sanitize_input
from modules.agent import generate_response
from modules.detector import detect_scam_hybrid, get_scam_categories,get_primary_category
from modules.extractor import DataExtractor


# Callback URL for sending scam intelligence
CALLBACK_URL = os.getenv("CALLBACK_URL", "")
primary_category = ""

# Timeout configuration
ENDPOINT_TIMEOUT = 25  # 25 second max timeout for entire endpoint

# Initialize database on startup
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    "Lifespan context manager for FastAPI application. Handles startup events."
    #Startup
    print("Starting Up....")
    init_database()

    yield

# Initialize FastAPI app
app = FastAPI(title="AI Honeypot System", 
    description="Autonomous AI system to detect and engage with scammers", 
    version="1.0.0", 
    lifespan = lifespan)

# Dependency for API key authentication
async def verify_auth(x_api_key: Optional[str] = Header(None)) -> bool:
    """
    Verify API key from request header
    
    Args:
        x_api_key: API key from X-API-Key header
        
    Returns:
        True if authenticated
        
    Raises:
        HTTPException: If authentication fails
    """
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Include X-API-Key header."
        )
    
    if not verify_api_key(x_api_key):
        raise HTTPException(
            status_code=403,
            detail="Invalid or inactive API key"
        )
    
    return True


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.get("/ping")
async def ping():
    """Fast ping endpoint"""
    return {"status": "pong"}


async def send_callback(session_id: str, extracted_data: dict, message_count: int):
    """
    Send callback with extracted intelligence using async httpx
    Called when scam is confirmed and engagement is complete
    
    Args:
        session_id: The session ID
        extracted_data: Extracted scam data
        message_count: Total messages exchanged
    """
    if not CALLBACK_URL:
        print("No callback URL configured, skipping callback")
        return
    
    try:
        # Get all suspicious keywords
        keywords = SuspiciousKeywordManager.get_keywords(session_id)
        global primary_category        
        payload = {
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": message_count,
            "extractedIntelligence": {
                "bankAccounts": extracted_data.get("bank_accounts", []),
                "upiIds": extracted_data.get("upi_ids", []),
                "phishingLinks": extracted_data.get("phishing_links", []),
                "phoneNumbers": extracted_data.get("phone_numbers", []),
                "suspiciousKeywords": list(set(keywords))[:10]  # Top 10 unique keywords
            },
            "agentNotes": f"Engagement completed after {message_count} messages. Scam intelligence extracted with the primary category of scam detected as {primary_category}."
        }
        
        # Send POST request to callback URL using async httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                CALLBACK_URL,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
        
        if response.status_code == 200:
            print(f"Callback sent successfully for session {session_id}")
            SessionManager.mark_callback_sent(session_id)
        else:
            print(f"Callback failed with status {response.status_code}")
            
    except Exception as e:
        print(f"Error sending callback: {e}")


@app.post("/", response_model=MessageResponse)
async def root_message_endpoint(
    request: MessageRequest,
    authenticated: bool = Depends(verify_auth)
) -> MessageResponse:
    """
    Main message endpoint at root path
    Handles incoming scammer messages via POST to /
    
    Args:
        request: MessageRequest containing message and conversation history
        authenticated: Authentication status from dependency
        
    Returns:
        MessageResponse with AI-generated reply
    """
    try:
        # Wrap main processing in timeout
        async def process_message():
            # Validate and sanitize session ID
            if not validate_session_id(request.sessionId):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid session ID format"
                )
            
            session_id = sanitize_input(request.sessionId, max_length=100)
            message_text = sanitize_input(request.message.text, max_length=2000)
            
            # Get or create session
            session = SessionManager.get_session(session_id)
            if not session:
                SessionManager.create_or_update_session(
                    session_id=session_id,
                    channel=request.metadata.channel if request.metadata else None,
                    language=request.metadata.language if request.metadata else None,
                    locale=request.metadata.locale if request.metadata else None
                )
                session = SessionManager.get_session(session_id)
            
            # Build conversation history for context
            conversation_texts = [msg.text for msg in request.conversationHistory]
            
            # Step 1: Detect scam using hybrid approach (keyword + AI if needed)
            is_scam, confidence, matched_keywords = detect_scam_hybrid(
                message_text, 
                conversation_texts,
                use_ai=True  # Enable AI detection after keyword match
            )
            
            # Step 2: Extract data from the message (both regex and AI) if message is detected as scam
            extracted_data = DataExtractor().get_extracted_data()  # Initialize empty
            if is_scam and confidence >= 0.5:
                extractor = DataExtractor()
                extractor.extract_from_text(message_text, use_ai=True)
                extracted_data = extractor.get_extracted_data()
                scam_categories = get_scam_categories(message_text)
                global primary_category
                primary_category = get_primary_category(scam_categories)
            
            # Prepare batch data for efficient database writes
            extraction_batch = []
            if extracted_data.has_data():
                for account in extracted_data.bank_accounts:
                    extraction_batch.append(("bank_accounts", account))
                for upi in extracted_data.upi_ids:
                    extraction_batch.append(("upi_ids", upi))
                for link in extracted_data.phishing_links:
                    extraction_batch.append(("phishing_links", link))
                for phone in extracted_data.phone_numbers:
                    extraction_batch.append(("phone_numbers", phone))
            
            # Format conversation history for the agent
            conversation_history = [
                {
                    'sender': msg.sender,
                    'text': msg.text,
                    'timestamp': msg.timestamp
                }
                for msg in request.conversationHistory
            ]
            
            # Step 3: Generate AI response
            ai_response = generate_response(
                message=message_text,
                conversation_history=conversation_history
            )
            
            # Batch database writes for performance optimization
            # Save incoming message
            MessageManager.save_message(
                session_id=session_id,
                sender=request.message.sender,
                text=message_text,
                timestamp=request.message.timestamp
            )
            
            # Save AI response
            MessageManager.save_message(
                session_id=session_id,
                sender="user",
                text=ai_response,
                timestamp=request.message.timestamp + 1000  # Add 1 second
            )
            
            # Save extracted data in batch
            if extraction_batch:
                ExtractedDataManager.save_extracted_data_batch(session_id, extraction_batch)
            
            # Save suspicious keywords in batch
            if matched_keywords:
                SuspiciousKeywordManager.save_keywords_batch(session_id, matched_keywords)
            
            # Update session metadata
            if is_scam and confidence > session.get("scam_confidence", 0.0):
                SessionManager.update_scam_status(session_id, True, confidence)
            
            # Increment message count (2 messages: incoming + response)
            SessionManager.increment_message_count(session_id)
            SessionManager.increment_message_count(session_id)
            
            # Get updated message count from session
            updated_session = SessionManager.get_session(session_id)
            message_count = updated_session.get("message_count", 0)
            
            # Check if we should send callback
            # Criteria: scam detected, high confidence, sufficient messages, data extracted
            # IMPORTANT: Only send callback ONCE per session (check callback_sent flag)
            should_send_callback = (
                is_scam and 
                confidence >= 0.6 and 
                message_count >= 6 and  # At least 3 exchanges
                extracted_data.has_data() and
                not updated_session.get("callback_sent", False)  # Only if not already sent
            )
            
            # Send callback AFTER all processing is complete, but BEFORE returning response
            if should_send_callback:
                # Get all extracted data accumulated across the entire conversation
                all_extracted = ExtractedDataManager.get_extracted_data(session_id)
                
                # Send callback asynchronously (fire and forget to not block response)
                # But mark session IMMEDIATELY to prevent duplicate callbacks
                SessionManager.mark_callback_sent(session_id)
                asyncio.create_task(send_callback(session_id, all_extracted, message_count))
            
            # Return the AI response (always respond, even after callback is sent)
            return MessageResponse(
                status="success",
                reply=ai_response
            )
        
        # Execute with timeout
        try:
            return await asyncio.wait_for(process_message(), timeout=ENDPOINT_TIMEOUT)
        except asyncio.TimeoutError:
            print(f"Request timeout after {ENDPOINT_TIMEOUT}s")
            # Return a fallback response on timeout
            return MessageResponse(
                status="success",
                reply="sorry im a bit confused can u explain again?"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in message endpoint: {e}")
        return MessageResponse(
            status="error",
            error=f"Internal server error: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)