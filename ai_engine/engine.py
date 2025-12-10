from .embedding import Embedder
from .database import VectorDB

class AIEngine:
    def __init__(self):
        self.embedder = Embedder()
        self.db = VectorDB()
        
    def analyze_log(self, log_text):
        """
        Retrieves context for a log entry using RAG.
        Returns the closest match from the VectorDB (or None).
        """
        # 1. Embed the log
        vector = self.embedder.embed(log_text)
        
        # 2. Query the DB
        result = self.db.query_log(vector)
        
        return result

    def learn_log(self, text, is_threat, severity="Medium", remediation="None"):
        """
        Learns from a new log entry by adding it to the vector DB.
        """
        vector = self.embedder.embed(text)
        metadata = {
            "severity": severity,
            "remediation": remediation,
            "is_threat": str(is_threat) # Store as string for metadata compatibility
        }
        
        # We only add it to the threat signatures if it IS a threat.
        # If it's safe, we could add it to a "safe" collection, but for now
        # we just want to expand the threat knowledge base.
        # Actually, to support "Mark as Safe", we should probably have a way to know it's safe.
        # But per the plan, we are adding "examples".
        # If is_threat is False, we might not want to add it to "threat_signatures" unless we have a "safe_signatures" collection.
        # For simplicity in this low-compute version, let's assume we are primarily "Teaching it Threats".
        # But if the user says "This is safe", we should probably NOT match it as a threat.
        # Let's stick to the plan: Add to DB.
        # We will add a "type" metadata field.
        
        metadata["type"] = "threat" if is_threat else "safe"
        
        self.db.add_threat_signature(text, metadata, vector)
        return {"status": "learned", "id": str(hash(text))}
