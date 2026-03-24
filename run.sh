#!/bin/bash

# Define text colors for better visibility
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}    WebAnalyzer Full Suite Launcher    ${NC}"
echo -e "${BLUE}=======================================${NC}"

# Navigate to the correct directory just in case
cd "$(dirname "$0")"

# Start the Python FastAPI Backend
echo -e "\n${GREEN}[1/2] Starting FastAPI Backend Server...${NC}"
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "Warning: No venv directory found. Make sure dependencies are installed globally."
fi

# Run uvicorn in the background and save its PID
uvicorn api:app --reload --port 8000 &
BACKEND_PID=$!

# Start the React / Vite Dashboard
echo -e "${GREEN}[2/2] Starting React Dashboard...${NC}"
cd dashboard || { echo "Dashboard directory not found!"; kill $BACKEND_PID; exit 1; }

# Run Vite dev server in the background and save its PID
npm run dev &
FRONTEND_PID=$!

# Confirmation
echo -e "\n${BLUE}=======================================${NC}"
echo -e "${GREEN}✔ Services successfully started!${NC}"
echo -e "   Backend API : ${BLUE}http://127.0.0.1:8000${NC}"
echo -e "   React Panel : ${BLUE}http://localhost:5173${NC}"
echo -e "${BLUE}=======================================${NC}"
echo -e "Press ${GREEN}Ctrl+C${NC} to gracefully stop both services."

# Trap Ctrl+C (SIGINT) to kill both background processes
trap "echo -e '\n${BLUE}[*] Stopping WebAnalyzer services...${NC}'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" SIGINT SIGTERM

# Wait indefinitely until interrupted
wait
