#!/bin/bash

# Email TLS Passive Forensics Framework - Unified Startup Script
# Boots FastAPI Backend (port 8000) and Vite React Frontend (port 5173)

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "================================================================="
echo "  Starting Email TLS Passive Network Forensics Framework"
echo "================================================================="

# Trap SIGINT and SIGTERM to kill background subprocesses cleanly
cleanup() {
    echo ""
    echo "[!] Shutting down framework servers..."
    kill $(jobs -p) 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

# Check Python environment
if [ -d "backend/venv" ]; then
    source backend/venv/bin/activate
fi

# Start FastAPI backend
echo "[+] Starting FastAPI backend on http://127.0.0.1:8000..."
cd backend
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!
cd "$SCRIPT_DIR"

# Wait for backend health endpoint to respond
echo "[+] Waiting for backend server to initialize..."
sleep 2

# Start React Frontend
echo "[+] Starting React Frontend dashboard on http://localhost:5173..."
cd frontend
if [ ! -d "node_modules" ]; then
    echo "[*] Installing frontend node packages..."
    npm install
fi
npm run dev &
FRONTEND_PID=$!
cd "$SCRIPT_DIR"

echo ""
echo "================================================================="
echo "  Framework Operational:"
echo "    - Dashboard UI: http://localhost:5173"
echo "    - Backend API:  http://127.0.0.1:8000"
echo "    - API Docs:     http://127.0.0.1:8000/docs"
echo "  Press Ctrl+C to stop all services."
echo "================================================================="

wait $BACKEND_PID $FRONTEND_PID
