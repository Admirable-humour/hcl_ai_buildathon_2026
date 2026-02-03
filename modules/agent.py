"""
AI conversational agent using Gemini LLM for generating responses
"""
import os
from typing import List, Dict, Optional
from google import genai


# Configure Gemini API
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash-exp")

# Initialize Gemini client
_client = None
if GEMINI_API_KEY:
    _client = genai.Client(api_key=GEMINI_API_KEY)


class HoneypotAgent:
    """
    AI agent that engages with scammers using a believable persona
    """
    
    # System prompt to guide the AI's behavior
    SYSTEM_PROMPT = """You are playing the role of a concerned but somewhat naive person who has received a suspicious message. Your goal is to:

1. Act naturally curious and slightly worried
2. Ask clarifying questions to extract more information
3. Never reveal that you suspect this is a scam
4. Show hesitation but eventual willingness to comply
5. Ask for specific details (bank accounts, UPI IDs, links, etc.)
6. Make realistic typos or grammar mistakes occasionally
7. Express confusion about technical terms
8. Be cautious but not overly suspicious

Keep responses brief (1-2 sentences) and human-like. Gradually build trust with the scammer while extracting information."""
    
    def __init__(self, model_name: str = GEMINI_MODEL):
        """
        Initialize the Gemini-based honeypot agent
        
        Args:
            model_name: The Gemini model to use
        """
        self.model_name = model_name
        self.client = _client
    
    def _format_conversation_context(self, conversation_history: List[Dict[str, str]], 
                                    current_message: str) -> str:
        """
        Format conversation history and current message for the LLM
        
        Args:
            conversation_history: List of previous messages
            current_message: The latest message from the scammer
            
        Returns:
            Formatted conversation context string
        """
        context = self.SYSTEM_PROMPT + "\n\nConversation so far:\n"
        
        # Add conversation history
        for msg in conversation_history:
            sender = "Scammer" if msg['sender'] == 'scammer' else "You"
            context += f"{sender}: {msg['text']}\n"
        
        # Add current message
        context += f"Scammer: {current_message}\n"
        context += "\nYour response (as the concerned person):"
        
        return context
    
    def generate_response(self, message: str, 
                         conversation_history: Optional[List[Dict[str, str]]] = None) -> str:
        """
        Generate a response to the scammer's message
        
        Args:
            message: The latest message from the scammer
            conversation_history: Previous messages in the conversation
            
        Returns:
            Generated response text
        """
        if not self.client:
            # Fallback responses if Gemini is not configured
            return self._get_fallback_response(message, conversation_history or [])
        
        try:
            # Format the conversation context
            context = self._format_conversation_context(
                conversation_history or [], 
                message
            )
            
            # Generate response using Gemini
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=context,
                config={
                    "temperature": 0.9,
                    "top_p": 0.95,
                    "top_k": 40,
                    "max_output_tokens": 150,
                }
            )
            
            if response and response.text:
                return response.text.strip()
            else:
                return self._get_fallback_response(message, conversation_history or [])
                
        except Exception as e:
            print(f"Error generating response with Gemini: {e}")
            return self._get_fallback_response(message, conversation_history or [])
    
    def _get_fallback_response(self, message: str, 
                               conversation_history: List[Dict[str, str]]) -> str:
        """
        Generate fallback responses when Gemini is unavailable
        
        Args:
            message: The scammer's message
            conversation_history: Previous messages
            
        Returns:
            Fallback response text
        """
        message_lower = message.lower()
        msg_count = len(conversation_history)
        
        # First message responses
        if msg_count == 0:
            if 'block' in message_lower or 'suspend' in message_lower:
                return "Why will my account be blocked? I haven't done anything wrong."
            elif 'verify' in message_lower:
                return "Verify what? I didn't receive any notification from my bank."
            elif 'prize' in message_lower or 'won' in message_lower:
                return "Really? I don't remember entering any contest. What prize?"
            else:
                return "Is this message really from my bank?"
        
        # Follow-up responses
        if 'upi' in message_lower:
            return "My UPI ID? Why do you need that? Can't I verify another way?"
        elif 'account' in message_lower and 'number' in message_lower:
            return "You want my account number? Isn't it already in your system?"
        elif 'link' in message_lower or 'click' in message_lower:
            return "What link? I'm not very good with these things. Can you explain?"
        elif 'otp' in message_lower:
            return "OTP? I haven't received any OTP yet. Where will it come from?"
        elif 'urgent' in message_lower or 'immediately' in message_lower:
            return "Okay, I'm worried now. What exactly do I need to do?"
        else:
            return "I'm confused. Can you explain this more clearly?"


# Create a singleton instance for reuse
_agent_instance = None


def get_agent() -> HoneypotAgent:
    """
    Get or create the honeypot agent instance
    
    Returns:
        HoneypotAgent instance
    """
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = HoneypotAgent()
    return _agent_instance


def generate_response(message: str, 
                     conversation_history: Optional[List[Dict[str, str]]] = None) -> str:
    """
    Standalone function to generate a response
    
    Args:
        message: The scammer's message
        conversation_history: Previous conversation messages
        
    Returns:
        Generated response text
    """
    agent = get_agent()
    return agent.generate_response(message, conversation_history)
