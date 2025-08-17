#!/bin/bash
# Test script for IOCTLance API

API_URL="http://localhost:8080"
SAMPLE_DRIVER="samples/RtDashPt.sys"

echo "IOCTLance API Test Script"
echo "========================="
echo ""

# Check if API is running
echo "1. Checking API health..."
curl -s ${API_URL}/health | python3 -m json.tool
echo ""

# Upload a driver
echo "2. Uploading driver ${SAMPLE_DRIVER}..."
UPLOAD_RESPONSE=$(curl -s -X POST ${API_URL}/upload \
  -F "file=@${SAMPLE_DRIVER}")
echo $UPLOAD_RESPONSE | python3 -m json.tool

# Extract file hash from response
FILE_HASH=$(echo $UPLOAD_RESPONSE | python3 -c "import sys, json; print(json.load(sys.stdin)['file_hash'])")
echo "File hash: $FILE_HASH"
echo ""

# Start analysis
echo "3. Starting analysis..."
ANALYSIS_RESPONSE=$(curl -s -X POST ${API_URL}/analyze/${FILE_HASH} \
  -H "Content-Type: application/json" \
  -d '{"timeout": 30, "complete_mode": false}')
echo $ANALYSIS_RESPONSE | python3 -m json.tool

# Extract job ID
JOB_ID=$(echo $ANALYSIS_RESPONSE | python3 -c "import sys, json; print(json.load(sys.stdin)['job_id'])")
echo "Job ID: $JOB_ID"
echo ""

# Check status
echo "4. Checking job status..."
sleep 2
curl -s ${API_URL}/status/${JOB_ID} | python3 -m json.tool
echo ""

# Wait for completion
echo "5. Waiting for analysis to complete (max 60 seconds)..."
for i in {1..60}; do
  STATUS=$(curl -s ${API_URL}/status/${JOB_ID} | python3 -c "import sys, json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
  if [ "$STATUS" = "completed" ]; then
    echo "Analysis completed!"
    break
  elif [ "$STATUS" = "failed" ]; then
    echo "Analysis failed!"
    curl -s ${API_URL}/status/${JOB_ID} | python3 -m json.tool
    exit 1
  fi
  echo -n "."
  sleep 1
done
echo ""

# Get result
echo "6. Getting analysis result..."
curl -s ${API_URL}/result/${JOB_ID} | python3 -m json.tool | head -50
echo ""

# List all jobs
echo "7. Listing all jobs..."
curl -s ${API_URL}/jobs | python3 -m json.tool
echo ""

echo "API test completed successfully!"