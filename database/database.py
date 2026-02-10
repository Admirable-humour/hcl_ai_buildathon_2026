"""
SQLite database initialization and models.
"""
import sqlite3
import json
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
import os


DATABASE_PATH = os.getenv("DATABASE_PATH", "honeypot.db")


def init_database():
    """Initialize the SQLite database with required tables"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Sessions table - stores conversation sessions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            is_scam BOOLEAN DEFAULT 0,
            message_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            channel TEXT,
            language TEXT,
            locale TEXT,
            scam_confidence REAL DEFAULT 0.0,
            callback_sent BOOLEAN DEFAULT 0
        )
    ''')
    
    # Messages table - stores all conversation messages
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            text TEXT NOT NULL,
            timestamp BIGINT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    ''')
    
    # Extracted data table - stores extracted scam information
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS extracted_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            data_type TEXT NOT NULL,
            data_value TEXT NOT NULL,
            extracted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    ''')
    
    # Suspicious keywords table - stores matched scam keywords for faster detection
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS suspicious_keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            keyword TEXT NOT NULL,
            matched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    ''')
    
    # Create indices for better query performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_extracted_session ON extracted_data(session_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_keywords_session ON suspicious_keywords(session_id)')
    
    conn.commit()
    conn.close()


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


class SessionManager:
    """Manages conversation sessions in the database"""
    
    @staticmethod
    def create_or_update_session(session_id: str, channel: Optional[str] = None, 
                                 language: Optional[str] = None, locale: Optional[str] = None):
        """Create a new session or update existing one"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (session_id, channel, language, locale, message_count)
                VALUES (?, ?, ?, ?, 0)
                ON CONFLICT(session_id) DO UPDATE SET
                    last_activity = CURRENT_TIMESTAMP
            ''', (session_id, channel, language, locale))
    
    @staticmethod
    def update_scam_status(session_id: str, is_scam: bool, confidence: float = 0.0):
        """Update scam detection status and confidence for a session"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions 
                SET is_scam = ?, scam_confidence = ?
                WHERE session_id = ?
            ''', (is_scam, confidence, session_id))
    
    @staticmethod
    def increment_message_count(session_id: str):
        """Increment message count for a session"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions 
                SET message_count = message_count + 1, last_activity = CURRENT_TIMESTAMP
                WHERE session_id = ?
            ''', (session_id,))
    
    @staticmethod
    def mark_callback_sent(session_id: str):
        """Mark that callback has been sent for this session"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions 
                SET callback_sent = 1
                WHERE session_id = ?
            ''', (session_id,))
    
    @staticmethod
    def get_session(session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session information"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            return dict(row) if row else None


class MessageManager:
    """Manages conversation messages in the database"""
    
    @staticmethod
    def save_message(session_id: str, sender: str, text: str, timestamp: int):
        """Save a message to the database"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO messages (session_id, sender, text, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (session_id, sender, text, timestamp))
    
    @staticmethod
    def get_conversation_history(session_id: str) -> List[Dict[str, Any]]:
        """Retrieve all messages for a session"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT sender, text, timestamp FROM messages 
                WHERE session_id = ? ORDER BY timestamp ASC
            ''', (session_id,))
            return [dict(row) for row in cursor.fetchall()]


class ExtractedDataManager:
    """Manages extracted scam data in the database"""
    
    @staticmethod
    def save_extracted_data(session_id: str, data_type: str, data_value: str):
        """Save extracted data to the database"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Check if this exact data already exists to avoid duplicates
            cursor.execute('''
                SELECT id FROM extracted_data 
                WHERE session_id = ? AND data_type = ? AND data_value = ?
            ''', (session_id, data_type, data_value))
            
            if not cursor.fetchone():
                cursor.execute('''
                    INSERT INTO extracted_data (session_id, data_type, data_value)
                    VALUES (?, ?, ?)
                ''', (session_id, data_type, data_value))
    
    @staticmethod
    def save_extracted_data_batch(session_id: str, data: List[Tuple[str, str]]):
        """
        Save multiple extracted data items in a single transaction
        Optimizes database writes by batching operations
        
        Args:
            session_id: The session ID
            data: List of tuples (data_type, data_value)
        """
        if not data:
            return
            
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Prepare data for batch insert, avoiding duplicates
            to_insert = []
            for data_type, data_value in data:
                cursor.execute('''
                    SELECT id FROM extracted_data 
                    WHERE session_id = ? AND data_type = ? AND data_value = ?
                ''', (session_id, data_type, data_value))
                
                if not cursor.fetchone():
                    to_insert.append((session_id, data_type, data_value))
            
            # Batch insert
            if to_insert:
                cursor.executemany('''
                    INSERT INTO extracted_data (session_id, data_type, data_value)
                    VALUES (?, ?, ?)
                ''', to_insert)
    
    @staticmethod
    def get_extracted_data(session_id: str) -> Dict[str, List[str]]:
        """Retrieve all extracted data for a session"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT data_type, data_value FROM extracted_data 
                WHERE session_id = ? ORDER BY extracted_at ASC
            ''', (session_id,))
            
            result = {
                'bank_accounts': [],
                'upi_ids': [],
                'phishing_links': [],
                'phone_numbers': [],
                'suspicious_keywords': []
            }
            
            for row in cursor.fetchall():
                data_type = row['data_type']
                data_value = row['data_value']
                if data_type in result:
                    result[data_type].append(data_value)
            
            return result


class SuspiciousKeywordManager:
    """Manages suspicious keywords matched in conversations"""
    
    @staticmethod
    def save_keywords_batch(session_id: str, keywords: List[str]):
        """
        Save multiple keywords in a single transaction
        
        Args:
            session_id: The session ID
            keywords: List of matched keywords
        """
        if not keywords:
            return
            
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Insert keywords (allow duplicates as they show frequency)
            data = [(session_id, keyword) for keyword in keywords]
            cursor.executemany('''
                INSERT INTO suspicious_keywords (session_id, keyword)
                VALUES (?, ?)
            ''', data)
    
    @staticmethod
    def get_keywords(session_id: str) -> List[str]:
        """Get all matched keywords for a session"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT keyword FROM suspicious_keywords 
                WHERE session_id = ? ORDER BY matched_at ASC
            ''', (session_id,))
            
            return [row['keyword'] for row in cursor.fetchall()]


# Initialize database on module import
init_database()
