#!/bin/bash

echo "🛡️  LogWarden - Starting All Services..."

# Kill existing processes
echo "Stopping existing processes..."
pkill -9 -f uvicorn 2>/dev/null
pkill -9 -f "next-server" 2>/dev/null
pkill -9 -f "python collector" 2>/dev/null
pkill -9 -f "generate_traffic" 2>/dev/null
lsof -ti:3000 | xargs kill -9 2>/dev/null
lsof -ti:8000 | xargs kill -9 2>/dev/null

sleep 2

# Ensure AI Model is available (Pre-pull for smooth demo)
echo "🧠 Ensuring AI Model (Llama 3.2) is ready..."
docker exec security-officer-ai ollama pull llama3.2 > /dev/null 2>&1 &


# Start Backend
echo "🔧 Starting Backend API (port 8000)..."
export LICENSE_KEY=${LICENSE_KEY:-"LW-DEV-KEY-12345"}
cd core-api
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 > backend.log 2>&1 &
BACKEND_PID=$!
echo "   Backend PID: $BACKEND_PID"
cd ..

sleep 2

# Start Frontend
echo "🎨 Starting Frontend Dashboard (port 3000)..."
cd dashboard
npm run dev > frontend.log 2>&1 &
FRONTEND_PID=$!
echo "   Frontend PID: $FRONTEND_PID"
cd ..

sleep 2

# Start Collector
echo "📊 Starting Real Log Collector..."
python collector-linux/collector.py > collector.log 2>&1 &
COLLECTOR_PID=$!
echo "   Collector PID: $COLLECTOR_PID"

sleep 1

# Start Traffic Generator
echo "🚨 Starting Attack Traffic Simulator..."
./generate_traffic.sh > traffic.log 2>&1 &
TRAFFIC_PID=$!
echo "   Traffic Generator PID: $TRAFFIC_PID"

echo ""
echo "✅ All services started!"
echo ""
echo "📍 Services:"
echo "   - Backend API:       http://localhost:8000"
echo "   - Frontend Dashboard: http://localhost:3000"
echo "   - Real Log Collector: Running"
echo "   - Traffic Simulator:  Running"
echo ""
echo "📋 Process IDs:"
echo "   - Backend:   $BACKEND_PID"
echo "   - Frontend:  $FRONTEND_PID"
echo "   - Collector: $COLLECTOR_PID"
echo "   - Traffic:   $TRAFFIC_PID"
echo ""
echo "📄 Logs:"
echo "   - Backend:   core-api/backend.log"
echo "   - Frontend:  dashboard/frontend.log"
echo "   - Collector: collector.log"
echo "   - Traffic:   traffic.log"
echo ""
echo "🌐 Open http://localhost:3000 in your browser!"
echo ""
echo "To stop all services, run: pkill -f uvicorn; pkill -f next-server; pkill -f collector; pkill -f generate_traffic"
