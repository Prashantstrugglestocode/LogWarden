#!/bin/bash

echo "Starting LogWarden AI Core..."

# Check if ollama is installed
if ! command -v ollama &> /dev/null; then
    echo "Error: ollama is not installed. Please install it from https://ollama.com"
    exit 1
fi

# Start ollama serve in background if not running
if ! pgrep -x "ollama" > /dev/null; then
    echo "Starting Ollama server..."
    ollama serve &
    sleep 5
else
    echo "Ollama server is already running."
fi

# Pull the model
MODEL="qwen2.5:1.5b"
echo "Checking for model $MODEL..."
ollama pull $MODEL

echo "AI Core is ready!"
echo "Model: $MODEL"
