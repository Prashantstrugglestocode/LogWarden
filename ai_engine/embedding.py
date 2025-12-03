import os
from sentence_transformers import SentenceTransformer

class Embedder:
    def __init__(self, model_name="all-MiniLM-L6-v2"):
        print(f"Loading embedding model: {model_name}...")
        self.model = SentenceTransformer(model_name)
        print("Model loaded.")

    def embed(self, text):
        """
        Converts text to a vector (list of floats).
        """
        # encode returns a numpy array, convert to list for storage
        return self.model.encode(text).tolist()

if __name__ == "__main__":
    # Test
    emb = Embedder()
    vector = emb.embed("This is a test log entry.")
    print(f"Vector length: {len(vector)}")
