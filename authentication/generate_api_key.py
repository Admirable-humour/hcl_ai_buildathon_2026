#!/usr/bin/env python3
"""
Utility script to generate API keys for the honeypot system
Usage: 
  From root: python authentication/generate_api_key.py [key_name]
  From auth dir: python generate_api_key.py [key_name]
"""

import sys
import os

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Change to root directory if in authentication folder
if os.path.basename(os.getcwd()) == 'authentication':
    os.chdir('..')

from authentication.auth import create_api_key


def main():
    # Get key name from command line or use default
    key_name = sys.argv[1] if len(sys.argv) > 1 else "default-key"
    
    print("Generating API key...")
    api_key, success = create_api_key(key_name)
    
    if success:
        print("\n" + "=" * 60)
        print("✅ API Key Generated Successfully!")
        print("=" * 60)
        print(f"\nKey Name: {key_name}")
        print(f"API Key:  {api_key}")
        print("\n⚠️  IMPORTANT: Save this key securely!")
        print("   This key will not be shown again.")
        print("   Use it in the X-API-Key header for all API requests.")
        print("=" * 60)
    else:
        print("\n❌ Failed to generate API key")
        print("   Please check database configuration and try again.")
        sys.exit(1)


if __name__ == "__main__":
    main()
