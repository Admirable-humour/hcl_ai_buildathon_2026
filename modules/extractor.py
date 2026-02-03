"""
Data extraction module for extracting bank details, UPI IDs, phishing links
"""
import re
from typing import List, Dict
from dataclasses import dataclass, field


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
    """Extract scam-related data from text messages"""
    
    # Regex patterns for different data types
    BANK_ACCOUNT_PATTERN = r'\b\d{9,18}\b'  # 9-18 digit bank account numbers
    UPI_ID_PATTERN = r'\b[\w\.-]+@[\w\.-]+\b'  # UPI ID format: user@bank
    URL_PATTERN = r'https?://[^\s]+|www\.[^\s]+|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+'
    PHONE_PATTERN = r'\b(?:\+91[\s-]?)?[6-9]\d{9}\b'  # Indian phone numbers
    IFSC_PATTERN = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'  # IFSC code pattern
    
    def __init__(self):
        """Initialize the data extractor"""
        self.data = ScamData()
    
    def extract_from_text(self, text: str) -> ScamData:
        """
        Extract all types of data from a single text message
        
        Args:
            text: The message text to analyze
            
        Returns:
            ScamData object containing extracted information
        """
        if not text:
            return self.data
        
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
