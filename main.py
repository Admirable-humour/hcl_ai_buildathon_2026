"""
FastAPI main application for AI Honeypot System
"""
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from typing import Optional
import os

# Import modules
from database.schemas import ChatRequest, ChatResponse, SessionInfo, ExtractedData
from database.database import (
    SessionManager, MessageManager, ExtractedDataManager, init_database
)
from authentication.auth import verify_api_key, validate_session_id, sanitize_input
from modules.agent import generate_response
from modules.detector import detect_scam, get_scam_category
from modules.extractor import DataExtractor


# Initialize FastAPI app
app = FastAPI(
    title="AI Honeypot System",
    description="Autonomous AI system to detect and engage with scammers",
    version="1.0.0"
)


# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database when the application starts"""
    init_database()


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


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AI Honeypot System API",
        "version": "1.0.0",
        "status": "active"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(
    request: ChatRequest,
    authenticated: bool = Depends(verify_auth)
) -> ChatResponse:
    """
    Main chat endpoint to handle incoming scammer messages
    
    Args:
        request: ChatRequest containing message and conversation history
        authenticated: Authentication status from dependency
        
    Returns:
        ChatResponse with AI-generated reply
    """
    try:
        # Validate and sanitize session ID
        if not validate_session_id(request.sessionId):
            raise HTTPException(
                status_code=400,
                detail="Invalid session ID format"
            )
        
        session_id = sanitize_input(request.sessionId, max_length=100)
        message_text = sanitize_input(request.message.text, max_length=2000)
        
        # Create or update session
        SessionManager.create_or_update_session(
            session_id=session_id,
            channel=request.metadata.channel if request.metadata else None,
            language=request.metadata.language if request.metadata else None,
            locale=request.metadata.locale if request.metadata else None
        )
        
        # Save incoming message to database
        MessageManager.save_message(
            session_id=session_id,
            sender=request.message.sender,
            text=message_text,
            timestamp=request.message.timestamp
        )
        
        # Detect scam in the message
        is_scam, confidence, matched_keywords = detect_scam(message_text)
        
        # Update scam status if detected
        if is_scam:
            SessionManager.update_scam_status(session_id, True)
            scam_category = get_scam_category(message_text)
        
        # Extract data from the message
        extractor = DataExtractor()
        extractor.extract_from_text(message_text)
        extracted_data = extractor.get_extracted_data()
        
        # Save extracted data to database
        if extracted_data.has_data():
            for account in extracted_data.bank_accounts:
                ExtractedDataManager.save_extracted_data(
                    session_id, "bank_accounts", account
                )
            for upi in extracted_data.upi_ids:
                ExtractedDataManager.save_extracted_data(
                    session_id, "upi_ids", upi
                )
            for link in extracted_data.phishing_links:
                ExtractedDataManager.save_extracted_data(
                    session_id, "phishing_links", link
                )
            for phone in extracted_data.phone_numbers:
                ExtractedDataManager.save_extracted_data(
                    session_id, "phone_numbers", phone
                )
        
        # Format conversation history for the agent
        conversation_history = [
            {
                'sender': msg.sender,
                'text': msg.text,
                'timestamp': msg.timestamp
            }
            for msg in request.conversationHistory
        ]
        
        # Generate AI response
        ai_response = generate_response(
            message=message_text,
            conversation_history=conversation_history
        )
        
        # Save AI response to database
        MessageManager.save_message(
            session_id=session_id,
            sender="user",
            text=ai_response,
            timestamp=request.message.timestamp + 1000  # Add 1 second
        )
        
        # Increment message count
        SessionManager.increment_message_count(session_id)
        
        return ChatResponse(
            status="success",
            reply=ai_response
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in chat endpoint: {e}")
        return ChatResponse(
            status="error",
            error=f"Internal server error: {str(e)}"
        )


@app.get("/sessions/{session_id}", response_model=SessionInfo)
async def get_session_info(
    session_id: str,
    authenticated: bool = Depends(verify_auth)
) -> SessionInfo:
    """
    Get information about a specific session
    
    Args:
        session_id: The session ID to retrieve
        authenticated: Authentication status
        
    Returns:
        SessionInfo with session details and extracted data
    """
    try:
        # Validate session ID
        if not validate_session_id(session_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid session ID format"
            )
        
        # Get session from database
        session = SessionManager.get_session(session_id)
        if not session:
            raise HTTPException(
                status_code=404,
                detail="Session not found"
            )
        
        # Get extracted data
        extracted_dict = ExtractedDataManager.get_extracted_data(session_id)
        extracted_data = ExtractedData(**extracted_dict)
        
        return SessionInfo(
            sessionId=session['session_id'],
            is_scam=bool(session['is_scam']),
            message_count=session['message_count'],
            created_at=session['created_at'],
            last_activity=session['last_activity'],
            extracted_data=extracted_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting session info: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/sessions/{session_id}/messages")
async def get_session_messages(
    session_id: str,
    authenticated: bool = Depends(verify_auth)
):
    """
    Get all messages for a specific session
    
    Args:
        session_id: The session ID
        authenticated: Authentication status
        
    Returns:
        List of messages
    """
    try:
        # Validate session ID
        if not validate_session_id(session_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid session ID format"
            )
        
        # Get messages from database
        messages = MessageManager.get_conversation_history(session_id)
        
        return {
            "sessionId": session_id,
            "messages": messages,
            "count": len(messages)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting session messages: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
