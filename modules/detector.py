"""
Scam detection module using keyword-based detection
"""
import re
from typing import List, Tuple


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
