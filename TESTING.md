# LogWarden Testing Guide

This repository includes a robust **Integration Test Suite** for the AI Agent. This allows you to verify the AI's "brain" without needing a full database or GPU environment.

## Key Test File
**File:** `core-api/tests/test_ai_integration.py`

This test suite uses **Python Mocks** to simulate:
1.  **The Database (RAG):** Simulates fetching "past logs".
2.  **The LLM (Ollama):** Simulates the AI returning a JSON response.
3.  **Graph API:** Simulates User Profiles (e.g., "Alice is an Admin").

## What We Test
1.  **Context Injection (Admins):**
    *   *Input:* `Failed login for admin@corp.com`
    *   *Verification:* We assert that the **Prompt sent to the AI** explicitly contains `Role=Administrator`.
    
2.  **Reputation Checks (Malicious IPs):**
    *   *Input:* `Connection from 51.15.99.10`
    *   *Verification:* We assert the Prompt contains `Status=Malicious`.

3.  **Robustness (Messy Output):**
    *   *Input:* LLM returns "Here is my thinking... ```json {...} ```"
    *   *Verification:* We assert the Parser correctly finds the JSON and ignores the chatbots chatter.

## How to Run
```bash
cd core-api
python3 tests/test_ai_integration.py
```
**Success Output:**
```
✅ Admin Context successfully injected.
✅ Malicious IP Context successfully injected.
✅ Robust JSON Parsing verified.
OK
```
