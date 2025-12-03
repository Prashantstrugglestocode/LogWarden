import sys
import os

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ai_engine.engine import AIEngine

def debug():
    print("Initializing AI Engine...")
    engine = AIEngine()
    
    text = "SELECT * FROM users WHERE 1=1"
    print(f"Analyzing text: '{text}'")
    
    # Embed
    vector = engine.embedder.embed(text)
    
    # Query
    result = engine.db.query_log(vector)
    
    print("\n--- Result ---")
    print(result)

if __name__ == "__main__":
    debug()
