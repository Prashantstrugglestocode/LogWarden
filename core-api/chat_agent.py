from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from agent import query_ollama
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("chat-agent")

router = APIRouter()

class ChatRequest(BaseModel):
    message: str
    history: list = []

@router.post("/chat")
async def chat_with_agent(request: ChatRequest):
    """
    Chat endpoint for the support bot.
    """
    try:
        user_msg = request.message
        
        # System prompt to guide the AI's persona
        system_prompt = """You are the 'LogWarden Support Agent', a helpful and knowledgeable security expert.
        Your goal is to assist users with questions about the LogWarden dashboard, security threats, and general cybersecurity best practices.
        
        Product Context:
        - LogWarden is a local, AI-powered security dashboard.
        - It detects threats like Brute Force, SQL Injection, and more.
        - It runs 100% locally on Docker (privacy focused).
        - It uses Llama 3.2 for reasoning.
        
        Guidelines:
        - Be concise and friendly.
        - If you don't know the answer, say "I'm not sure, please check the documentation."
        - Do not hallucinate features we don't have.
        - If the user asks about a specific log, ask them to provide the log ID.
        
        User Query:
        """
        
        full_prompt = f"{system_prompt}\n{user_msg}\n\nAnswer:"
        
        # Using the existing query_ollama function (which returns a dict often, but here we just want text if possible)
        # However, query_ollama in agent.py is designed to return JSON.
        # We might need a raw text version or we can instruct it to return JSON with a 'response' field.
        
        # Enhanced prompt for JSON output compatibility with existing agent infrastructure
        json_prompt = f"""
        {system_prompt}
        {user_msg}
        
        Output strictly in JSON format:
        {{
            "response": "Your helpful answer here..."
        }}
        """
        
        result = await query_ollama(json_prompt)
        
        if result and "response" in result:
            return {"response": result["response"]}
        else:
            # Fallback if JSON parsing fails or model hallucinates format
            logger.warning("AI did not return valid JSON, returning generic error.")
            return {"response": "I'm having trouble processing that right now. Please try again."}

    except Exception as e:
        logger.error(f"Chat Error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
