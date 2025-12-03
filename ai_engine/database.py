import chromadb
import os
import time

class VectorDB:
    def __init__(self, persist_directory=None):
        if persist_directory is None:
            persist_directory = os.path.join(os.path.dirname(__file__), "chroma_db")
        self.client = chromadb.PersistentClient(path=persist_directory)
        self.collection = self.client.get_or_create_collection(name="threat_signatures")

    def add_threat_signature(self, text, metadata, embedding):
        """
        Adds a known threat signature to the database.
        """
        # ID can be hash of text or just timestamp
        unique_id = str(hash(text))
        
        self.collection.add(
            documents=[text],
            metadatas=[metadata],
            embeddings=[embedding],
            ids=[unique_id]
        )

    def query_log(self, log_embedding, n_results=1):
        """
        Finds the most similar threat signature.
        """
        results = self.collection.query(
            query_embeddings=[log_embedding],
            n_results=n_results
        )
        
        if not results['documents'][0]:
            return None
            
        return {
            "document": results['documents'][0][0],
            "metadata": results['metadatas'][0][0],
            "distance": results['distances'][0][0]
        }
