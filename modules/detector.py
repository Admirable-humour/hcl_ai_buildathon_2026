"""
Scam detection module using hybrid keyword + AI-based detection

Edge Cases to Handle:
- Gemini API rate limit exceeded - fallback to keyword-only detection
- Gemini API timeout - use cached results or keyword detection
- Ambiguous messages - rely on conversation context
"""
import re
import os
import json
import time
from typing import List, Tuple, Optional
from google import genai


# Configure Gemini API for AI-based detection
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemma-3-27b-it" #Higher Parameter model for better analysis and detection.

# Timeout configuration
DETECTOR_TIMEOUT = 10  # 10 second timeout for detection

# Initialize Gemini client
_client = None
if GEMINI_API_KEY:
    _client = genai.Client(api_key=GEMINI_API_KEY)


# Common scam keywords and phrases (case-insensitive)
PRIZE_PATTERNS = [
    r"\bcongratulations?\b",
    r"\bwinners?\b",
    r"\blottery\b",
    r"\brewards?\b",
    r"\bcashback\b",
    r"won.*prize",
    r"claim.*prize",
]

# Strong patterns: alone should be high-confidence
STRONG_PATTERNS = [
    r"\botps?\b",
    r"\b(mpin|pin)s?\b",
    r"\bpasswords?\b",
    r"\bcvv\b",
    r"\bbit\.ly\b",
    r"\btinyurl\b",
    r"\bupis?\b",
    r"\bifsc\b",
    r"\baccounts?\b.*\bnumbers?\b",
]

# Weak patterns: should NOT alone classify as scam (reduce false positives)
WEAK_PATTERNS = [
    r"\burgent(ly)?\b",
    r"\bimmediate(ly)?\b",
    r"\basap\b",
    r"\bnow\b",
    r"\btoday\b",
    r"\bexpir(e|ed|ing)\b",
    r"\bkindly\b",
    r"do.*needful",
    r"revert.*back",
    r"\bofficial\b.*\bnotice\b",
    r"\bbank\b.*\bnotification\b",
    r"\brefunds?\b",
]

# Action-request patterns (often scam when paired with weak/strong)
ACTION_PATTERNS = [
    r"https?://[^\s)\]}>,\"']+",
    r"click.*links?",
    r"verify.*links?",
    r"update.*details?",
    r"share.*details?",
    r"provide.*details?",
    r"send.*details?",
    r"confirm.*otps?",
    r"verify.*accounts?",
    r"confirm.*accounts?",
    r"update.*accounts?",
    r"accounts?.*blocks?",
    r"accounts?.*suspends?",
    r"accounts?.*deactivates?",
    r"accounts?.*closes?",
]

def _safe_json_load(s: str) -> Optional[dict]:
    """
    Gemini sometimes returns JSON in code fences or extra text.
    This extracts the first {...} block and parses it safely.
    """
    if not s:
        return None
    s = s.strip()
    # Remove markdown code fences
    s = re.sub(r"^```(?:json)?\s*|\s*```$", "", s, flags=re.IGNORECASE)
    # Extract first JSON object
    m = re.search(r"\{.*?\}", s, flags=re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        try:
            return json.loads(m.group(0).replace("'", '"'))
        except json.JSONDecodeError:
            return None

def _match_patterns(text_lower: str, patterns: List[str]) -> List[str]:
    matched = []
    for p in patterns:
        match = re.search(p, text_lower)
        if match:
            matched.append(match.group(0))
    return matched

def detect_scam(text: str, threshold: float = 0.5) -> Tuple[bool, float, List[str]]:
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
    matched_strong = _match_patterns(text_lower, STRONG_PATTERNS)
    matched_action = _match_patterns(text_lower, ACTION_PATTERNS)
    matched_weak = _match_patterns(text_lower, WEAK_PATTERNS)
    matched_prize = _match_patterns(text_lower, PRIZE_PATTERNS)

    matched_all = matched_strong + matched_action + matched_weak+ matched_prize
    
    weak_count = len(matched_weak)
    action_count = len(matched_action)
    # Calculate confidence score based on number of matches
    # More matches = higher confidence
    if matched_strong:
        confidence = 0.85
    elif action_count >= 2 and weak_count >= 1:
        confidence = 0.75
    elif matched_action and (matched_weak or matched_prize):
        confidence = 0.70
    elif matched_action:
        confidence = 0.55
    elif matched_prize and matched_weak:
        confidence = 0.45
    elif matched_prize:
        confidence = 0.30   # prize-only: track as suspicious but not "scam" by default
    elif weak_count >= 2:
        confidence = 0.35
    else:
        confidence = 0.0

    is_scam = confidence >= threshold
    return is_scam, confidence, matched_all


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
        is_scam, confidence, _ = detect_scam(message, threshold=0.4)
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
    
    is_scam = avg_confidence >= 0.5
    
    return is_scam, avg_confidence


def get_scam_categories(text: str) -> List[str]:
    """
    Categorize the type of scam based on keywords
    
    Args:
        text: The message text to categorize
        
    Returns:
        List indicating scam categories
    """
    if not text:
        return ["general_scam"]
    text_lower = text.lower()
    
    cats: List[str] = []

    # High-risk / financial credential scams
    if re.search(r"\bupi\b|\bifsc\b|\baccount\b.*\bnumber\b|\bbank\b.*(detail|details|info|information|account)", text_lower):
        cats.append("financial_phishing")

    # OTP / credential theft
    if re.search(r"\botp\b|\bcvv\b|\b(mpin|pin)\b|\bpassword\b", text_lower):
        cats.append("otp_scam")

    # Account threat / scare tactics
    if re.search(r"account.*(block|suspend|deactivate|close)", text_lower):
        cats.append("account_threat")

    # Link phishing / short links
    if re.search(r"https?://[^\s)\]}>,\"']+|\bbit\.ly\b|\btinyurl\b", text_lower) or re.search(r"click.*link|verify.*link", text_lower):
        cats.append("phishing_link")

    # Prize / reward scams (lower severity)
    if re.search(r"prize|winner|lottery|won|reward|cashback|claim", text_lower):
        cats.append("prize_scam")

    if not cats:
        cats.append("general_scam")

    return cats


def get_primary_category(categories: List[str]) -> str:
    """
    Pick one primary category by severity order for reporting.
    """
    priority = [
        "otp_scam",
        "financial_phishing",
        "phishing_link",
        "account_threat",
        "prize_scam",
        "general_scam",
    ]
    for p in priority:
        if p in categories:
            return p
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
        is_scam_kw, conf_kw, _ = detect_scam(text, threshold=0.5)
        return is_scam_kw, conf_kw
    
    try:
        # Create prompt for scam detection
        prompt = f"""Analyze if this message is a scam attempt involving phishing, financial fraud, urgency tactics, impersonation, or requests for sensitive information, considering various scam types occurring in India. Analyze the message word by word carefully without missing any detail but be fast and precise with your output. Message: "{text}"
Respond with ONLY a JSON object: {{"is_scam": true/false, "confidence": 0.0-1.0, "reason": "brief explanation in one or two sentences."}}"""

        # Only include last 2 messages for context to reduce token count
        if conversation_history:
            prompt += f"\nContext: {' | '.join(conversation_history[-2:])}"
        
        # Call Gemini API with timeout tracking
        start_time = time.time()
        response = _client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config={
                "temperature": 0.08,  # Low temperature for consistent detection
                "max_output_tokens": 80,  # Sufficient for detailed analysis
            }
        )
        
        elapsed = time.time() - start_time
        if elapsed > DETECTOR_TIMEOUT:
            print(f"Detector AI took {elapsed:.2f}s, using keyword fallback")
            is_scam_kw, conf_kw, _ = detect_scam(text, threshold=0.5)
            return is_scam_kw, conf_kw
        
        if response and response.text:
            # Parse JSON response
            result = _safe_json_load(response.text)
            if result:
                conf_raw = result.get("confidence", 0.0)
                try:
                    conf = float(conf_raw)
                except (TypeError, ValueError):
                    conf = 0.0
                return bool(result.get("is_scam", False)), conf

        
        is_scam_kw, conf_kw, _ = detect_scam(text, threshold=0.5)
        return is_scam_kw, conf_kw
        
    except Exception as e:
        print(f"Error in AI scam detection: {e}")
        is_scam_kw, conf_kw, _ = detect_scam(text, threshold=0.5)
        return is_scam_kw, conf_kw


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
    is_scam_kw, confidence_kw, keywords = detect_scam(text, threshold=0.5)
    
    # Step 2: If keywords suggest potential scam, invoke AI for confirmation
    if use_ai and confidence_kw >= 0.35 and _client:
        is_scam_ai, confidence_ai = detect_scam_with_ai(text, conversation_history)
        
        # Combine keyword and AI confidence
        # Use max so strong keyword signals (e.g., OTP/UPI/link) can't be "downgraded" by AI noise.
        combined_confidence = max(confidence_kw, confidence_ai)
        is_scam = (combined_confidence >= 0.5) or is_scam_ai
        
        return is_scam, combined_confidence, keywords
    
    # Fallback to keyword-only detection
    return is_scam_kw, confidence_kw, keywords
