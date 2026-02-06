"""
Data extraction module for extracting bank details, UPI IDs, phishing links
Uses both regex patterns and AI-based extraction

Edge Cases to Handle:
- Gemini API failures - fallback to regex-only extraction
- Malformed data (partial phone numbers, invalid UPIs) - validation before storing
- Unicode characters in data - proper encoding/decoding
"""
import re
import os
import json
import time
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from google import genai


# Configure Gemini API for AI-based extraction
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemma-3-27b-it"

# Timeout configuration
EXTRACTOR_TIMEOUT = 10  # 10 second timeout for extraction

# Initialize Gemini client
_client = None
if GEMINI_API_KEY:
    _client = genai.Client(api_key=GEMINI_API_KEY)


@dataclass
class ScamData:
    """
    Class to store extracted scam-related data
    Can be instantiated and used across different modules
    """
    bank_accounts: List[str] = field(default_factory=list)
    upi_ids: List[str] = field(default_factory=list)
    phishing_links: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    
    def add_bank_account(self, account: str):
        """Add a bank account if not already present"""
        if account and account not in self.bank_accounts:
            self.bank_accounts.append(account)
    
    def add_upi_id(self, upi: str):
        """Add a UPI ID if not already present"""
        if upi and upi not in self.upi_ids:
            self.upi_ids.append(upi)
    
    def add_phishing_link(self, link: str):
        """Add a phishing link if not already present"""
        if link and link not in self.phishing_links:
            self.phishing_links.append(link)
    
    def add_phone_number(self, phone: str):
        """Add a phone number if not already present"""
        if phone and phone not in self.phone_numbers:
            self.phone_numbers.append(phone)
    
    def to_dict(self) -> Dict[str, List[str]]:
        """Convert to dictionary format"""
        return {
            'bank_accounts': self.bank_accounts,
            'upi_ids': self.upi_ids,
            'phishing_links': self.phishing_links,
            'phone_numbers': self.phone_numbers
        }
    
    def has_data(self) -> bool:
        """Check if any data has been extracted"""
        return bool(self.bank_accounts or self.upi_ids or 
                   self.phishing_links or self.phone_numbers)


class DataExtractor:
    """Extract scam-related data from text messages using regex and AI"""
    
    # Regex patterns for different data types
    # Indian bank accounts: 9-18 digits, but NOT preceded/followed by letters
    # This prevents matching "16 digit" or "SBI" as account numbers
    BANK_ACCOUNT_PATTERN = r'(?<![a-zA-Z])\b(\d{9,18})\b(?![a-zA-Z])'
    
    UPI_ID_PATTERN = r'[\w\.-]+@[\w\.-]+'  # UPI ID format: user@bank
    
    # Enhanced URL pattern to catch more obfuscated links
    URL_PATTERN = r'(?xi)(?:(?:https?|hxxp)://|www\.|\b\d{1,3}(?:\.\d{1,3}){3}\b)[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+|(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|buff\.ly|is\.gd|short\.ly|shr\.tn)/[^\s)>\]]*'
    
    PHONE_PATTERN = r'\b(?:\+91[\s-]?)?[6-9]\d{9}\b'  # Indian phone numbers
    IFSC_PATTERN = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'  # IFSC code pattern
    
    # Words to exclude from bank account matching (common false positives)
    BANK_ACCOUNT_EXCLUDE_WORDS = {
        'digit', 'number', 'account', 'code', 'pin', 'otp', 'cvv', 
        'mobile', 'phone', 'contact', 'sbi', 'hdfc', 'icici', 'axis',
        'pnb', 'bob', 'canara', 'union', 'indian', 'bank'
    }
    
    def __init__(self):
        """Initialize the data extractor"""
        self.data = ScamData()
    
    def _is_valid_bank_account(self, account: str, context: str) -> bool:
        """
        Validate if extracted number is actually a bank account
        
        Args:
            account: The potential bank account number
            context: Surrounding text for context validation
            
        Returns:
            True if valid bank account, False otherwise
        """
        # Must be numeric only
        if not account.isdigit():
            return False
        
        # Length validation: Indian bank accounts are typically 9-18 digits
        # But 16 digits alone is suspicious (could be card number mention)
        account_len = len(account)
        if account_len < 9 or account_len > 18:
            return False
        
        # Check if it's likely a phone number (10 digits starting with 6-9)
        if account_len == 10 and account[0] in '6789':
            return False
        
        # Get 20 characters before and after for context
        context_lower = context.lower()
        account_pos = context_lower.find(account)
        if account_pos != -1:
            start = max(0, account_pos - 20)
            end = min(len(context_lower), account_pos + len(account) + 20)
            surrounding = context_lower[start:end]
            
            # Reject if surrounded by exclude words
            for word in self.BANK_ACCOUNT_EXCLUDE_WORDS:
                if word in surrounding:
                    return False
            
            # Reject if part of phrases like "16 digit account"
            if re.search(r'\d+\s*digit', surrounding):
                return False
        
        return True
    
    def _extract_with_ai(self, text: str) -> ScamData:
        """
        Use AI to extract scam-related data from text
        
        Args:
            text: The message text to analyze
            
        Returns:
            ScamData object with AI-extracted information
        """
        if not _client:
            return ScamData()
        
        try:
            prompt = f"""Extract ONLY actual scam data from: "{text}"

Rules:
- bank_accounts: ONLY numeric strings of 9-18 digits that are ACTUAL bank account numbers (NOT "16 digit" or bank names like "SBI")
- upi_ids: Format user@bank (e.g., scammer@paytm)
- phishing_links: URLs or shortened links
- phone_numbers: 10-digit Indian numbers starting with 6-9

Return JSON: {{"bank_accounts": [], "upi_ids": [], "phishing_links": [], "phone_numbers": []}}
Use empty [] if none found. Be precise - do not extract descriptive text."""

            start_time = time.time()
            response = _client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config={
                    "temperature": 0.05,  # Very low temperature for precise extraction
                    "max_output_tokens": 150,
                }
            )
            
            elapsed = time.time() - start_time
            if elapsed > EXTRACTOR_TIMEOUT:
                print(f"Extractor AI took {elapsed:.2f}s, timeout")
                return ScamData()
            
            if response and response.text:
                # Clean response text - remove markdown code blocks
                text_clean = response.text.strip()
                text_clean = re.sub(r'^```(?:json)?\s*', '', text_clean)
                text_clean = re.sub(r'\s*```$', '', text_clean)
                
                # Try to parse JSON
                result = json.loads(text_clean)
                ai_data = ScamData()
                
                # Validate bank accounts from AI
                for account in result.get("bank_accounts", []):
                    account_str = str(account).strip()
                    # Only accept if it's purely numeric and valid length
                    if account_str.isdigit() and 9 <= len(account_str) <= 18:
                        ai_data.add_bank_account(account_str)
                
                for upi in result.get("upi_ids", []):
                    ai_data.add_upi_id(str(upi))
                for link in result.get("phishing_links", []):
                    ai_data.add_phishing_link(str(link))
                for phone in result.get("phone_numbers", []):
                    ai_data.add_phone_number(str(phone))
                
                return ai_data
        
        except json.JSONDecodeError as e:
            print(f"JSON decode error in AI extraction: {e}")
        except Exception as e:
            print(f"Error in AI extraction: {e}")
        
        return ScamData()
    
    def extract_from_text(self, text: str, use_ai: bool = True) -> ScamData:
        """
        Extract all types of data from a single text message using hybrid approach
        
        Args:
            text: The message text to analyze
            use_ai: Whether to use AI extraction in addition to regex
            
        Returns:
            ScamData object containing extracted information
        """
        if not text:
            return self.data
        
        # Step 1: Regex-based extraction (fast, reliable)
        # Extract bank account numbers with strict validation
        potential_accounts = re.findall(self.BANK_ACCOUNT_PATTERN, text)
        for account in potential_accounts:
            if self._is_valid_bank_account(account, text):
                self.data.add_bank_account(account)
        
        # Extract UPI IDs
        upi_ids = re.findall(self.UPI_ID_PATTERN, text)
        for upi in upi_ids:
            # Validate UPI ID format (should have @ symbol and proper structure)
            if '@' in upi and not upi.startswith('@') and not upi.endswith('@'):
                # Ensure it's not an email-like pattern with spaces
                if ' ' not in upi:
                    self.data.add_upi_id(upi)
        
        # Extract URLs/links
        urls = re.findall(self.URL_PATTERN, text, re.IGNORECASE)
        for url in urls:
            # Clean trailing punctuation
            url = url.rstrip('.,;:!?')
            self.data.add_phishing_link(url)
        
        # Extract phone numbers
        phones = re.findall(self.PHONE_PATTERN, text)
        for phone in phones:
            # Clean up the phone number
            clean_phone = re.sub(r'[\s-]', '', phone)
            self.data.add_phone_number(clean_phone)
        
        # Step 2: AI-based extraction (for complex/obfuscated data)
        if use_ai and _client:
            ai_data = self._extract_with_ai(text)
            
            # Merge AI results with regex results (with validation)
            for account in ai_data.bank_accounts:
                # Double-check AI extracted accounts
                if account.isdigit() and 9 <= len(account) <= 18:
                    self.data.add_bank_account(account)
            
            for upi in ai_data.upi_ids:
                self.data.add_upi_id(upi)
            for link in ai_data.phishing_links:
                self.data.add_phishing_link(link)
            for phone in ai_data.phone_numbers:
                self.data.add_phone_number(phone)
        
        return self.data
    
    def extract_from_conversation(self, messages: List[str]) -> ScamData:
        """
        Extract data from entire conversation history
        
        Args:
            messages: List of message texts from the conversation
            
        Returns:
            ScamData object containing all extracted information
        """
        for message in messages:
            self.extract_from_text(message)
        
        return self.data
    
    def get_extracted_data(self) -> ScamData:
        """
        Get the current extracted data
        
        Returns:
            ScamData object
        """
        return self.data
    
    def reset(self):
        """Reset the extracted data"""
        self.data = ScamData()


def extract_data_from_text(text: str) -> Dict[str, List[str]]:
    """
    Standalone function to extract data from text
    
    Args:
        text: The message text to analyze
        
    Returns:
        Dictionary containing extracted data
    """
    extractor = DataExtractor()
    data = extractor.extract_from_text(text)
    return data.to_dict()


def extract_data_from_conversation(messages: List[str]) -> Dict[str, List[str]]:
    """
    Standalone function to extract data from conversation
    
    Args:
        messages: List of message texts
        
    Returns:
        Dictionary containing extracted data
    """
    extractor = DataExtractor()
    data = extractor.extract_from_conversation(messages)
    return data.to_dict()