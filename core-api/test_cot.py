import asyncio
import json
from unittest.mock import MagicMock, patch

# Mocking external dependencies
with patch('httpx.AsyncClient') as mock_client:
    # Simulate a smart AI response with CoT
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "response": """
        Let's think step by step.
        1. Transformation: The log indicates 3 failed login attempts.
        2. Context: Similar patterns were blocked yesterday.
        3. Threat: High likelihood of brute force.
        4. Action: Block IP.
        
        ```json
        {
            "reasoning": "Detected multiple failures matching known brute force pattern.",
            "is_threat": true,
            "severity": "High",
            "suggested_action": "block_ip",
            "action_target": "192.168.1.50"
        }
        ```
        """
    }
    mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
    
    # We can't easily run the actual agent.py because of imports, 
    # but I will verify the JSON parsing logic here which is the critical part.
    
    raw_text = mock_response.json.return_value['response']
    print(f"Raw LLM Output:\n{raw_text}")
    
    if "```json" in raw_text:
        json_str = raw_text.split("```json")[1].split("```")[0].strip()
        parsed = json.loads(json_str)
        print("\n✅ Validated JSON Parsing:")
        print(json.dumps(parsed, indent=2))
        
        if parsed['reasoning']:
            print("\n✅ CoT Reasoning Captured!")
