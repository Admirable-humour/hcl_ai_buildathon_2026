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
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemma-3-27b-it")

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
    BANK_ACCOUNT_PATTERN = r'\b\d{9,18}\b'  # 9-18 digit bank account numbers
    UPI_ID_PATTERN = r'[\w\.-]+@[\w\.-]+'  # UPI ID format: user@bank
    URL_PATTERN = r'https?://[^\s]+|www\.[^\s]+|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+'
    PHONE_PATTERN = r'\b(?:\+91[\s-]?)?[6-9]\d{9}\b'  # Indian phone numbers
    IFSC_PATTERN = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'  # IFSC code pattern
    
    def __init__(self):
        """Initialize the data extractor"""
        self.data = ScamData()
    
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
            prompt = f"""Extract scam data from: "{text}"
Return JSON: {{"bank_accounts": [], "upi_ids": [], "phishing_links": [], "phone_numbers": []}}
Use empty [] if none found. Analyse the messages word by word but be fast and precise with your output."""

            start_time = time.time()
            response = _client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config={
                    "temperature": 0.08,  # Low temperature for precise extraction
                    "max_output_tokens": 150,  # Adequate for extraction results
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
                
                for account in result.get("bank_accounts", []):
                    ai_data.add_bank_account(str(account))
                for upi in result.get("upi_ids", []):
                    ai_data.add_upi_id(str(upi))
                for link in result.get("phishing_links", []):
                    ai_data.add_phishing_link(str(link))
                for phone in result.get("phone_numbers", []):
                    ai_data.add_phone_number(str(phone))
                
                return ai_data
        
        except json.JSONDecodeError as e:
            print(f"Error in AI extraction: {e}")
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
        # Extract bank account numbers
        bank_accounts = re.findall(self.BANK_ACCOUNT_PATTERN, text)
        for account in bank_accounts:
            self.data.add_bank_account(account)
        
        # Extract UPI IDs
        upi_ids = re.findall(self.UPI_ID_PATTERN, text)
        for upi in upi_ids:
            # Validate UPI ID format (should have @ symbol)
            if '@' in upi and not upi.startswith('@') and not upi.endswith('@'):
                self.data.add_upi_id(upi)
        
        # Extract URLs/links
        urls = re.findall(self.URL_PATTERN, text, re.IGNORECASE)
        for url in urls:
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
            
            # Merge AI results with regex results
            for account in ai_data.bank_accounts:
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
