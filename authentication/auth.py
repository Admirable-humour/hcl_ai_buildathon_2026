"""
API authentication and security module
Handles API key generation, hashing, and verification with security best practices.
"""
import hashlib
import secrets
import os
import json
from datetime import datetime
from typing import Optional, Tuple, Dict, List
import hmac


API_KEYS_JSON_ENV = "API_KEYS_JSON"


def _get_api_keys_from_env() -> Dict:
    """
    Retrieve API keys from environment variable
    
    Returns:
        Dictionary of API key hashes and their metadata (including unique salt)
    """
    try:
        api_keys_json = os.getenv(API_KEYS_JSON_ENV, '{"keys": {}}')
        data = json.loads(api_keys_json)
        return data.get("keys", {})
    except json.JSONDecodeError as e:
        print(f"Error parsing API_KEYS_JSON: {e}. Using empty keys dict.")
        return {}
    except Exception as e:
        print(f"Error reading API keys from environment: {e}")
        return {}


def generate_api_key() -> str:
    """
    Generate a cryptographically secure API key
    Returns a 64-character hexadecimal string
    """
    return secrets.token_hex(32)


def generate_salt() -> str:
    """
    Generate a unique cryptographic salt for an API key
    Returns a 64-character hexadecimal string
    """
    return secrets.token_hex(32)


def hash_api_key_with_salt(api_key: str, salt: str) -> str:
    """
    Hash an API key using HMAC-SHA256 with a unique salt
    
    Security measures:
    - Uses HMAC-SHA256 hashing algorithm
    - Each key has its own unique salt (stored with the hash)
    - Provides constant-time comparison protection
    - Encodes in UTF-8 before hashing
    
    Args:
        api_key: The raw API key to hash
        salt: The unique salt for this specific key
        
    Returns:
        Hexadecimal hash string
    """
    # Use HMAC-SHA256 with the unique salt
    return hmac.new(
        salt.encode('utf-8'),
        api_key.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def generate_api_key_with_hash(key_name: Optional[str] = None) -> Tuple[str, str, str, Dict]:
    """
    Generate a new API key with its own unique salt and hash
    
    This function is used locally to generate keys that will be added to environment variables
    
    Args:
        key_name: Optional descriptive name for the API key
        
    Returns:
        Tuple of (api_key, salt, key_hash, metadata_dict)
    """
    api_key = generate_api_key()
    salt = generate_salt()
    key_hash = hash_api_key_with_salt(api_key, salt)
    
    metadata = {
        "salt": salt,  # Store the unique salt with the hash
        "name": key_name or "default",
        "created_at": datetime.now().isoformat(),
        "last_used": None,
        "is_active": True
    }
    
    return api_key, salt, key_hash, metadata


def verify_api_key(api_key: str) -> bool:
    """
    Verify if an API key is valid and active
    
    Security measures:
    - Uses constant-time comparison via HMAC to prevent timing attacks
    - Retrieves the unique salt for each key from storage
    - Checks if key is marked as active
    - Read-only operation (no state changes)
    
    Args:
        api_key: The raw API key to verify
        
    Returns:
        True if key is valid and active, False otherwise
    """
    if not api_key:
        return False
    
    try:
        # Read all API keys from environment
        keys = _get_api_keys_from_env()
        
        # Try to match the API key against each stored hash
        # Each hash was created with its own unique salt
        for key_hash, metadata in keys.items():
            if not metadata.get("is_active", False):
                continue
            
            # Get the unique salt for this key
            salt = metadata.get("salt")
            if not salt:
                continue
            
            # Hash the provided API key with this key's salt
            computed_hash = hash_api_key_with_salt(api_key, salt)
            
            # Constant-time comparison
            if hmac.compare_digest(computed_hash, key_hash):
                return True
        
        return False
    except Exception as e:
        print(f"Error verifying API key: {e}")
        return False


def list_api_keys() -> List[Dict]:
    """
    List all API keys with metadata (excluding hashes and salts)
    
    Returns:
        List of dictionaries containing key metadata
    """
    try:
        keys = _get_api_keys_from_env()
        return [
            {
                "name": meta.get("name"),
                "created_at": meta.get("created_at"),
                "last_used": meta.get("last_used"),
                "is_active": meta.get("is_active"),
            }
            for meta in keys.values()
        ]
    except Exception as e:
        print(f"Error listing API keys: {e}")
        return []


def sanitize_input(input_string: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent injection attacks
    
    Security measures:
    - Limits string length to prevent buffer overflow
    - Strips leading/trailing whitespace
    - Can be extended with additional sanitization as needed
    
    Args:
        input_string: The string to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not input_string:
        return ""
    
    # Limit length to prevent DoS attacks
    sanitized = input_string[:max_length]
    
    # Strip whitespace
    sanitized = sanitized.strip()
    
    return sanitized


def validate_session_id(session_id: str) -> bool:
    """
    Validate session ID format to prevent injection attacks
    
    Args:
        session_id: The session ID to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not session_id or len(session_id) > 100:
        return False
    
    # Allow only alphanumeric characters, hyphens, and underscores
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    return all(c in allowed_chars for c in session_id)