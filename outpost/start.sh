#!/bin/bash
# start.sh — Start both the background pipeline loop and the FastAPI server

echo "=== Launching Outpost Worker ==="
pkintel run all --loop --interval 30 &

echo "=== Launching Outpost API Server ==="
# Hugging Face Spaces expects the app on port 7860
uvicorn pkintel.api.app:app --host 0.0.0.0 --port 7860
