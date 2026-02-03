"""
Scam detection module using hybrid keyword + AI-based detection

Edge Cases to Handle:
- Gemini API rate limit exceeded - fallback to keyword-only detection
- Gemini API timeout - use cached results or keyword detection
- Ambiguous messages - rely on conversation context
"""
import re
import os
from typing import List, Tuple, Optional
from google import genai


# Configure Gemini API for AI-based detection
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash-exp")

# Initialize Gemini client
_client = None
if GEMINI_API_KEY:
    _client = genai.Client(api_key=GEMINI_API_KEY)


# Common scam keywords and phrases (case-insensitive)
SCAM_KEYWORDS = [
    # Account/Banking threats
    "account.*block", "account.*suspend", "account.*close", "account.*deactivate",
    "verify.*account", "confirm.*account", "update.*account",
    
    # Urgency indicators
    "immediate", "urgent", "asap", "now", "today", "within.*hour",
    "expire", "expiring", "expired",
    
    # Financial terms
    "upi", "bank.*detail", "account.*number", "ifsc", "cvv", "pin",
    "payment.*fail", "transaction.*fail", "refund",
    
    # Authority impersonation
    "bank.*notification", "official.*notice", "government",
    "tax.*department", "income.*tax", "gst",
    
    # Action requests
    "click.*link", "verify.*link", "update.*detail", "share.*detail",
    "provide.*detail", "send.*detail", "confirm.*otp",
    
    # Prize/Offer scams
    "congratulation", "winner", "won.*prize", "claim.*prize",
    "lottery", "reward", "cashback",
    
    # Suspicious links
    "bit\\.ly", "tinyurl", "short.*link",
    
    # Common scammer phrases
    "kindly", "do.*needful", "revert.*back"
]


def detect_scam(text: str, threshold: float = 0.3) -> Tuple[bool, float, List[str]]:
    """
    Detect if a message is likely a scam based on keyword matching
    
    Args:
        text: The message text to analyze
        threshold: Minimum confidence score to classify as scam (0.0 to 1.0)
        
    Returns:
        Tuple of (is_scam, confidence_score, matched_keywords)
    """
    if not text:
        return False, 0.0, []
    
    text_lower = text.lower()
    matched_keywords = []
    
    # Check for keyword matches
    for pattern in SCAM_KEYWORDS:
        if re.search(pattern, text_lower):
            matched_keywords.append(pattern)
    
    # Calculate confidence score based on number of matches
    # More matches = higher confidence
    if not matched_keywords:
        confidence = 0.0
    elif len(matched_keywords) == 1:
        confidence = 0.4
    elif len(matched_keywords) == 2:
        confidence = 0.6
    elif len(matched_keywords) == 3:
        confidence = 0.8
    else:
        confidence = 0.95
    
    is_scam = confidence >= threshold
    
    return is_scam, confidence, matched_keywords


def analyze_conversation_context(messages: List[str]) -> Tuple[bool, float]:
    """
    Analyze entire conversation history for scam patterns
    
    Args:
        messages: List of message texts from the conversation
        
    Returns:
        Tuple of (is_scam, confidence_score)
    """
    if not messages:
        return False, 0.0
    
    total_confidence = 0.0
    scam_message_count = 0
    
    for message in messages:
        is_scam, confidence, _ = detect_scam(message)
        if is_scam:
            scam_message_count += 1
            total_confidence += confidence
    
    if scam_message_count == 0:
        return False, 0.0
    
    # Average confidence across all scam messages
    avg_confidence = total_confidence / scam_message_count
    
    # If multiple messages show scam patterns, increase overall confidence
    if scam_message_count > 1:
        avg_confidence = min(0.99, avg_confidence * 1.2)
    
    is_scam = avg_confidence >= 0.3
    
    return is_scam, avg_confidence


def get_scam_category(text: str) -> str:
    """
    Categorize the type of scam based on keywords
    
    Args:
        text: The message text to categorize
        
    Returns:
        String indicating scam category
    """
    text_lower = text.lower()
    
    if re.search(r'upi|account.*number|bank.*detail', text_lower):
        return "financial_phishing"
    elif re.search(r'prize|winner|lottery|won', text_lower):
        return "prize_scam"
    elif re.search(r'otp|verify|confirm', text_lower):
        return "otp_scam"
    elif re.search(r'account.*block|suspend|deactivate', text_lower):
        return "account_threat"
    elif re.search(r'click.*link|bit\.ly|tinyurl', text_lower):
        return "phishing_link"
    else:
        return "general_scam"


def detect_scam_with_ai(text: str, conversation_history: Optional[List[str]] = None) -> Tuple[bool, float]:
    """
    Use AI (Gemini) to detect scam patterns in text
    This is invoked only after keyword detection suggests scam potential
    
    Args:
        text: The message text to analyze
        conversation_history: Previous messages for context
        
    Returns:
        Tuple of (is_scam, confidence_score)
    """
    if not _client:
        # Fallback if Gemini not configured
        return False, 0.0
    
    try:
        # Create prompt for scam detection
        prompt = f"""Analyze this message and determine if it's a scam attempt. Consider:
- Phishing attempts
- Financial fraud
- Urgency tactics
- Impersonation of authorities
- Request for sensitive information

Message: "{text}"

Respond with ONLY a JSON object:
{{"is_scam": true/false, "confidence": 0.0-1.0, "reason": "brief explanation"}}"""

        if conversation_history:
            prompt += f"\n\nPrevious context: {' | '.join(conversation_history[-3:])}"
        
        # Call Gemini API
        response = _client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config={
                "temperature": 0.1,  # Low temperature for consistency
                "max_output_tokens": 100,
            }
        )
        
        if response and response.text:
            # Parse JSON response
            import json
            result = json.loads(response.text.strip())
            return result.get("is_scam", False), result.get("confidence", 0.0)
        
        return False, 0.0
        
    except Exception as e:
        print(f"Error in AI scam detection: {e}")
        return False, 0.0


def detect_scam_hybrid(text: str, conversation_history: Optional[List[str]] = None, 
                       use_ai: bool = True) -> Tuple[bool, float, List[str]]:
    """
    Hybrid scam detection: First use keywords, then AI if threshold met
    
    Args:
        text: The message text to analyze
        conversation_history: Previous messages for context
        use_ai: Whether to use AI detection (default True)
        
    Returns:
        Tuple of (is_scam, confidence_score, matched_keywords)
    """
    # Step 1: Keyword-based detection (fast)
    is_scam_kw, confidence_kw, keywords = detect_scam(text)
    
    # Step 2: If keywords suggest potential scam, invoke AI for confirmation
    if use_ai and confidence_kw >= 0.3 and _client:
        is_scam_ai, confidence_ai = detect_scam_with_ai(text, conversation_history)
        
        # Combine keyword and AI confidence
        # Weight: 40% keywords, 60% AI
        combined_confidence = (0.4 * confidence_kw) + (0.6 * confidence_ai)
        is_scam = combined_confidence >= 0.5
        
        return is_scam, combined_confidence, keywords
    
    # Fallback to keyword-only detection
    return is_scam_kw, confidence_kw, keywords
