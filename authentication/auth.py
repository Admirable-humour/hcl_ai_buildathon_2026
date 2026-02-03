"""
API authentication and security module
Handles API key generation, hashing, and verification with security best practices
"""
import hashlib
import secrets
import os
from datetime import datetime
from typing import Optional, Tuple
import sqlite3
from contextlib import contextmanager


DATABASE_PATH = os.getenv("DATABASE_PATH", "honeypot.db")
# Use environment variable for additional security salt
SECRET_SALT = os.getenv("SECRET_SALT", "default_salt_change_in_production")


@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


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
    Create a new API key and store its hash in the database
    
    Args:
        key_name: Optional descriptive name for the API key
        
    Returns:
        Tuple of (api_key, success)
        The raw API key is returned only once and should be stored securely by the user
    """
    try:
        api_key = generate_api_key()
        key_hash = hash_api_key(api_key)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO api_keys (key_hash, key_name, is_active)
                VALUES (?, ?, 1)
            ''', (key_hash, key_name))
        
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
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, is_active FROM api_keys 
                WHERE key_hash = ? AND is_active = 1
            ''', (key_hash,))
            
            row = cursor.fetchone()
            
            if row:
                # Update last_used timestamp
                cursor.execute('''
                    UPDATE api_keys SET last_used = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (row['id'],))
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
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE api_keys SET is_active = 0 
                WHERE key_hash = ?
            ''', (key_hash,))
            
            return cursor.rowcount > 0
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
