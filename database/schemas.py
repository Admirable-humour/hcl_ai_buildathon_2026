"""
Pydantic schemas for API request/response validation
"""
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Literal
from datetime import datetime


class Message(BaseModel):
    """Schema for a single message in the conversation"""
    sender: Literal["scammer", "user"]
    text: str = Field(..., min_length=1)
    timestamp: int = Field(..., gt=0)
    
    @field_validator('timestamp')
    @classmethod
    def validate_timestamp(cls, v: int) -> int:
        """Validate timestamp is in reasonable range (epoch milliseconds)"""
        if v < 0 or v > 9999999999999:  # Valid range for epoch ms
            raise ValueError('Invalid timestamp format')
        return v


class Metadata(BaseModel):
    """Optional metadata about the message source"""
    channel: Optional[Literal["SMS", "WhatsApp", "Email", "Chat"]] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class MessageRequest(BaseModel):
    """Schema for incoming message API requests"""
    sessionId: str = Field(..., min_length=1, max_length=100)
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = None
    
    @field_validator('sessionId')
    @classmethod
    def validate_session_id(cls, v: str) -> str:
        """Validate session ID format"""
        if not v or not v.strip():
            raise ValueError('Session ID cannot be empty')
        return v.strip()


class MessageResponse(BaseModel):
    """Schema for API response"""
    status: Literal["success", "error"]
    reply: Optional[str] = None
    error: Optional[str] = None
    
    @field_validator('reply', 'error')
    @classmethod
    def validate_message_content(cls, v: Optional[str]) -> Optional[str]:
        """Ensure either reply or error is present"""
        return v
