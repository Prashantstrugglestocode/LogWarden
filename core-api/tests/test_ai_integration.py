import unittest
import sys
import os
import json
from unittest.mock import MagicMock, patch, AsyncMock

# 1. SETUP MOCKS BEFORE IMPORTING AGENT
# We need to block DB connections
sys.modules['database'] = MagicMock()
sys.modules['models'] = MagicMock()
sys.modules['sqlalchemy'] = MagicMock()
sys.modules['sqlalchemy.orm'] = MagicMock()
sys.modules['httpx'] = MagicMock()

sys.modules['sqlalchemy'] = MagicMock()
sys.modules['sqlalchemy.orm'] = MagicMock()
sys.modules['httpx'] = MagicMock()
sys.modules['sentence_transformers'] = MagicMock()
sys.modules['chromadb'] = MagicMock()

# Configure CVSS Mock Return
cvss_mock = MagicMock()
cvss_mock.calculate_severity.return_value = ("Low", "Low")
sys.modules['cvss_calculator'] = cvss_mock

# Add parent path to import agent
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agent import analyze_security_event, AnalysisRequest, _extract_entities, _get_user_context, _check_ip_reputation

class TestAIIntegration(unittest.IsolatedAsyncioTestCase):
    
    async def test_admin_context_injection(self):
        """
        Verify that an 'Admin' user triggers the correct Context Injection in the prompt.
        We intercept the arguments passed to 'query_ollama' (which we mock).
        """
        # Data
        req = AnalysisRequest(
            log_message="Failed login via ssh for admin@corp.com",
            source="linux-server"
        )
        
        # Mocking the query_ollama function inside agent module
        # AND mocking the RAG engine to return "No Match" so we force LLM usage
        with patch('agent.query_ollama', new_callable=AsyncMock) as mock_llm, \
             patch('ai_engine.engine.AIEngine.analyze_log') as mock_rag:
            
            # RAG returns a "Weak Match" (distance 0.8) so we skip Tier 2 and go to Tier 3 (LLM)
            mock_rag.return_value = {
                "distance": 0.8, 
                "document": "some old log",
                "metadata": {"type": "info", "remediation": "none"}
            }

            # Setup LLM Return Value
            mock_llm.return_value = {
                "response": '```json\n{"is_threat": true, "severity": "Critical", "reasoning": "Admin user failed login"}\n```'
            }
            
            # Run
            await analyze_security_event(req)
            
            # Assert
            # Check what was sent to LLM
            # We need to guard against NoneType if the call failed
            if not mock_llm.called:
                self.fail("LLM was not called! Agent might have crashed or returned early.")
                
            call_args = mock_llm.call_args[0][0]
            print(f"\n[Test Admin] Prompt Sent:\n{call_args[:500]}...")
            
            self.assertIn("User 'admin@corp.com'", call_args)
            self.assertIn("Role=Administrator", call_args)
            self.assertIn("RiskLevel=high", call_args)
            print("✅ Admin Context successfully injected into Prompt.")

    async def test_malicious_ip_detection(self):
        """
        Verify that a known 'Malicious IP' triggers the prompt warning.
        """
        req = AnalysisRequest(
            log_message="Connection initiated from 51.15.99.10 port 443",
            source="firewall"
        )
        
        with patch('agent.query_ollama', new_callable=AsyncMock) as mock_llm, \
             patch('ai_engine.engine.AIEngine.analyze_log') as mock_rag:
             
            mock_rag.return_value = {"distance": 0.8, "document": "log", "metadata": {}}
            mock_llm.return_value = {
                "response": '{"is_threat": true, "severity": "High"}'
            }
            
            await analyze_security_event(req)
            
            if not mock_llm.called:
                self.fail("LLM not called")
            
            call_args = mock_llm.call_args[0][0]
            self.assertIn("IP '51.15.99.10'", call_args)
            self.assertIn("Reputation Score=90", call_args) 
            self.assertIn("Status=Malicious", call_args)
            print("✅ Malicious IP Context successfully injected into Prompt.")

    async def test_cot_parsing(self):
        """
        Verify the AI can parse messy CoT output.
        """
        req = AnalysisRequest(log_message="test", source="test")
        
        messy_response = """
        Thinking Process:
        1. Accessing log...
        2. It looks bad.
        
        JSON:
        ```json
        {
            "reasoning": "This is a test logic.",
            "is_threat": false, 
            "severity": "Low"
        }
        ```
        """
        
        with patch('agent.query_ollama', new_callable=AsyncMock) as mock_llm, \
             patch('ai_engine.engine.AIEngine.analyze_log') as mock_rag:
             
            mock_rag.return_value = {"distance": 0.8, "document": "log", "metadata": {}}
            mock_llm.return_value = {"response": messy_response}
            
            result = await analyze_security_event(req)
            
            # Since severity is Low and is_threat is False, it returns Low severity logic.
            # Wait, my assertion previously expected "Medium (Generative)".
            # In agent.py:
            # final_analysis = { "severity": analysis_json.get('severity', "Medium"), "confidence": "Medium (Generative)", ... }
            # So confidence IS "Medium (Generative)" if LLM is used.
            
            self.assertEqual(result['confidence'], "Medium (Generative)")
            self.assertEqual(result['severity'], "Low")
            print("✅ Robust JSON Parsing verified.")

if __name__ == '__main__':
    unittest.main()
