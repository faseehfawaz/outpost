#!/bin/bash
# start.sh — Start both the background pipeline loop and the FastAPI server

# Forward signals to children
trap 'kill -TERM $WORKER_PID $API_PID 2>/dev/null' TERM INT

echo "=== Launching Outpost Worker ==="
pkintel run all --loop --interval 30 &
WORKER_PID=$!

echo "=== Launching Outpost API Server ==="
# Hugging Face Spaces expects the app on port 7860
uvicorn pkintel.api.app:app --host 0.0.0.0 --port 7860 &
API_PID=$!

# Wait for either process to exit. 
# This ensures container health reflects worker health: if the worker dies, wait -n returns.
wait -n $WORKER_PID $API_PID
EXIT_CODE=$?

# If one dies, bring down the other
kill -TERM $WORKER_PID $API_PID 2>/dev/null
wait $WORKER_PID $API_PID 2>/dev/null

exit $EXIT_CODE
