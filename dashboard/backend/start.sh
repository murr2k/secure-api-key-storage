#!/bin/bash

# Secure API Key Storage Dashboard - Backend Startup Script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Secure API Key Storage Dashboard Backend...${NC}"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install -r requirements.txt

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Creating .env file from .env.example...${NC}"
    cp .env.example .env
    echo -e "${RED}Please edit .env file with your configuration before running!${NC}"
    exit 1
fi

# Load environment variables
export $(cat .env | grep -v '^#' | xargs)

# Check if master password is set
if [ -z "$API_KEY_MASTER" ]; then
    echo -e "${RED}Error: API_KEY_MASTER not set in .env file!${NC}"
    exit 1
fi

# Start the server
echo -e "${GREEN}Starting FastAPI server on http://localhost:8000${NC}"
echo -e "${GREEN}API documentation available at http://localhost:8000/docs${NC}"

# Development mode with auto-reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000