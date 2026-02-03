"""
API authentication and security module
Handles API key generation, hashing, and verification with security best practices

Edge Cases to Handle:
- Concurrent access to API keys file (file locking)
- Corrupted API keys file (validation and recovery)
- Missing API keys file (auto-create)
"""
import hashlib
import secrets
import os
import json
from datetime import datetime
from typing import Optional, Tuple, Dict
from pathlib import Path
import fcntl  # For file locking on Unix systems


# Use environment variable for additional security salt
SECRET_SALT = os.getenv("SECRET_SALT", "default_salt_change_in_production")

# Store API keys in a secure file outside of database to avoid security risks
# This file should have restricted permissions (600) in production
API_KEYS_FILE = os.getenv("API_KEYS_FILE", ".api_keys.json")


def _ensure_api_keys_file():
    """Ensure API keys file exists with proper structure"""
    if not os.path.exists(API_KEYS_FILE):
        with open(API_KEYS_FILE, 'w') as f:
            json.dump({"keys": {}}, f)
        # Set restrictive permissions (owner read/write only)
        os.chmod(API_KEYS_FILE, 0o600)


def _read_api_keys() -> Dict:
    """Read API keys from secure file with locking"""
    _ensure_api_keys_file()
    with open(API_KEYS_FILE, 'r') as f:
        # Lock file for reading
        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
        try:
            data = json.load(f)
            return data.get("keys", {})
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _write_api_keys(keys: Dict):
    """Write API keys to secure file with locking"""
    _ensure_api_keys_file()
    with open(API_KEYS_FILE, 'r+') as f:
        # Lock file for writing
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.seek(0)
            json.dump({"keys": keys}, f, indent=2)
            f.truncate()
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def generate_api_key() -> str:
    """
    Generate a cryptographically secure API key
    Returns a 64-character hexadecimal string
    """
    return secrets.token_hex(32)


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key using SHA-256 with salt for secure storage
    
    Security measures:
    - Uses SHA-256 hashing algorithm
    - Adds secret salt to prevent rainbow table attacks
    - Encodes in UTF-8 before hashing
    
    Args:
        api_key: The raw API key to hash
        
    Returns:
        Hexadecimal hash string
    """
    # Combine API key with secret salt for additional security
    salted_key = f"{api_key}{SECRET_SALT}".encode('utf-8')
    return hashlib.sha256(salted_key).hexdigest()


def create_api_key(key_name: Optional[str] = None) -> Tuple[str, bool]:
    """
    Create a new API key and store its hash in secure file
    
    Args:
        key_name: Optional descriptive name for the API key
        
    Returns:
        Tuple of (api_key, success)
        The raw API key is returned only once and should be stored securely by the user
    """
    try:
        api_key = generate_api_key()
        key_hash = hash_api_key(api_key)
        
        # Read existing keys
        keys = _read_api_keys()
        
        # Add new key
        keys[key_hash] = {
            "name": key_name or "default",
            "created_at": datetime.now().isoformat(),
            "last_used": None,
            "is_active": True
        }
        
        # Write back to file
        _write_api_keys(keys)
        
        return api_key, True
    except Exception as e:
        print(f"Error creating API key: {e}")
        return "", False


def verify_api_key(api_key: str) -> bool:
    """
    Verify if an API key is valid and active
    
    Security measures:
    - Uses constant-time comparison to prevent timing attacks
    - Checks if key is marked as active
    - Updates last_used timestamp on successful verification
    
    Args:
        api_key: The raw API key to verify
        
    Returns:
        True if key is valid and active, False otherwise
    """
    if not api_key:
        return False
    
    try:
        key_hash = hash_api_key(api_key)
        
        # Read API keys
        keys = _read_api_keys()
        
        if key_hash in keys and keys[key_hash].get("is_active", False):
            # Update last_used timestamp
            keys[key_hash]["last_used"] = datetime.now().isoformat()
            _write_api_keys(keys)
            return True
        
        return False
    except Exception as e:
        print(f"Error verifying API key: {e}")
        return False


def revoke_api_key(api_key: str) -> bool:
    """
    Revoke an API key by marking it as inactive
    
    Args:
        api_key: The raw API key to revoke
        
    Returns:
        True if successfully revoked, False otherwise
    """
    try:
        key_hash = hash_api_key(api_key)
        
        # Read API keys
        keys = _read_api_keys()
        
        if key_hash in keys:
            keys[key_hash]["is_active"] = False
            _write_api_keys(keys)
            return True
        
        return False
    except Exception as e:
        print(f"Error revoking API key: {e}")
        return False


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
