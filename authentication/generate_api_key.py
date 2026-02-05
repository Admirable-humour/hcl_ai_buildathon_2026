"""
Utility script to generate API keys for the honeypot system

Usage: 
  python authentication/generate_api_key.py [key_name]
  
Output:
  - Raw API key (save securely)
  - JSON snippet to add/update in Render's API_KEYS_JSON environment variable
"""

import sys
import os
import json

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from authentication.auth import generate_api_key_with_hash


def main():
    # Get key name from command line or use default
    key_name = sys.argv[1] if len(sys.argv) > 1 else "default-key"
    
    print("Generating API key with unique salt...")
    api_key, salt, key_hash, metadata = generate_api_key_with_hash(key_name)
    
    # Get existing keys from environment (if any)
    existing_keys_json = os.getenv("API_KEYS_JSON", '{"keys": {}}')
    try:
        existing_data = json.loads(existing_keys_json)
        existing_keys = existing_data.get("keys", {})
    except:
        existing_keys = {}
    
    # Add new key
    existing_keys[key_hash] = metadata
    
    # Create new JSON
    new_json = {"keys": existing_keys}
    new_json_str = json.dumps(new_json, indent=2)
    
    print("\n" + "=" * 70)
    print(" API Key Generated Successfully!")
    print("=" * 70)
    print(f"\n Key Name: {key_name}")
    print(f" API Key:  {api_key}\n")
    print(f" Salt:     {salt}\n")
    print(f" Hash:     {key_hash}\n")
    print("\n  IMPORTANT: Save the API key securely!")
    print("   This key will not be shown again.")
    print("   Use it in the X-API-Key header for all API requests.")
    print("\n Note: Each API key has its own unique salt stored with it.")
    print("   No shared SECRET_SALT needed!")
    print("=" * 70)
    
    print("\n You can add multiple keys to the same API_KEYS_JSON variable.")
    print("   Just run this script multiple times and copy the latest JSON output.")
    print("   Each key has its own independent salt - no conflicts!")
    print("=" * 70)
    
    # Also output compact version for easy copying
    compact_json = json.dumps(new_json)
    print("\n COMPACT VERSION (for easy copy-paste):")
    print(compact_json)
    print()


if __name__ == "__main__":
    main()