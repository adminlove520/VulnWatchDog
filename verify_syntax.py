import sys
import os

# Add current directory to path
sys.path.append(os.getcwd())

try:
    print("Attempting to import libs.utils...")
    from libs.utils import search_github
    print("Successfully imported libs.utils.search_github")
    print("Syntax check passed.")
except SyntaxError as e:
    print(f"SyntaxError: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Import Error: {e}")
    # It might fail due to other dependencies, but we are checking for SyntaxError specifically
    # If it's not a SyntaxError, we might be good on the syntax front.
    sys.exit(0) 
