#!/bin/bash
"""
IOCTLance REST API Client using curl

This script demonstrates how to use the IOCTLance REST API with curl
for uploading and analyzing Windows drivers.

Requirements:
    - curl
    - jq (for JSON parsing)
"""

# Configuration
API_URL="${API_URL:-http://localhost:8080}"
DRIVER_PATH="${1:-samples/RtDashPt.sys}"
TIMEOUT="${2:-120}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check dependencies
if ! command -v curl &> /dev/null; then
    echo -e "${RED}Error: curl is not installed${NC}"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}Warning: jq is not installed. Output will be less readable.${NC}"
    JQ="cat"
else
    JQ="jq"
fi

# Check if driver file exists
if [ ! -f "$DRIVER_PATH" ]; then
    echo -e "${RED}Error: Driver file not found: $DRIVER_PATH${NC}"
    exit 1
fi

echo "=========================================="
echo "IOCTLance API Client (curl)"
echo "=========================================="
echo "API: $API_URL"
echo "Driver: $DRIVER_PATH"
echo "Timeout: ${TIMEOUT}s"
echo "------------------------------------------"

# Check API health
echo -e "\n${YELLOW}Checking API health...${NC}"
HEALTH=$(curl -s "$API_URL/health")
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Cannot connect to API at $API_URL${NC}"
    exit 1
fi
echo "$HEALTH" | $JQ
echo -e "${GREEN}✓ API is healthy${NC}"

# Upload driver
echo -e "\n${YELLOW}Uploading driver...${NC}"
UPLOAD_RESPONSE=$(curl -s -X POST "$API_URL/upload" \
    -F "file=@$DRIVER_PATH")
    
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Upload failed${NC}"
    exit 1
fi

echo "$UPLOAD_RESPONSE" | $JQ

FILE_HASH=$(echo "$UPLOAD_RESPONSE" | jq -r '.file_hash' 2>/dev/null || echo "$UPLOAD_RESPONSE" | grep -oP '"file_hash"\s*:\s*"\K[^"]+')
if [ -z "$FILE_HASH" ] || [ "$FILE_HASH" = "null" ]; then
    echo -e "${RED}Error: Could not extract file hash from response${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Upload successful${NC}"
echo "  File hash: ${FILE_HASH:0:16}..."

# Start analysis
echo -e "\n${YELLOW}Starting analysis...${NC}"
ANALYSIS_RESPONSE=$(curl -s -X POST "$API_URL/analyze/$FILE_HASH" \
    -H "Content-Type: application/json" \
    -d "{\"timeout\": $TIMEOUT}")
    
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to start analysis${NC}"
    exit 1
fi

echo "$ANALYSIS_RESPONSE" | $JQ

JOB_ID=$(echo "$ANALYSIS_RESPONSE" | jq -r '.job_id' 2>/dev/null || echo "$ANALYSIS_RESPONSE" | grep -oP '"job_id"\s*:\s*"\K[^"]+')
if [ -z "$JOB_ID" ] || [ "$JOB_ID" = "null" ]; then
    echo -e "${RED}Error: Could not extract job ID from response${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Analysis started${NC}"
echo "  Job ID: ${JOB_ID:0:8}..."

# Poll for completion
echo -e "\n${YELLOW}Waiting for results...${NC}"
MAX_POLLS=$((($TIMEOUT + 30) / 2))
POLL_COUNT=0

while [ $POLL_COUNT -lt $MAX_POLLS ]; do
    sleep 2
    
    STATUS_RESPONSE=$(curl -s "$API_URL/status/$JOB_ID")
    STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.status' 2>/dev/null || echo "$STATUS_RESPONSE" | grep -oP '"status"\s*:\s*"\K[^"]+')
    
    if [ "$STATUS" = "completed" ]; then
        echo -e "\n${GREEN}✓ Analysis completed!${NC}\n"
        
        # Get full results
        echo -e "${YELLOW}Fetching results...${NC}"
        RESULT=$(curl -s "$API_URL/result/$JOB_ID")
        
        if command -v jq &> /dev/null; then
            # Pretty print with jq
            echo "$RESULT" | jq
            
            # Extract summary
            VULN_COUNT=$(echo "$RESULT" | jq '.vuln | length')
            IOCTL_HANDLER=$(echo "$RESULT" | jq -r '.ioctl_handler.address // "Unknown"')
            IOCTL_CODES=$(echo "$RESULT" | jq -r '.ioctl_handler.ioctl_codes | length // 0')
            ANALYSIS_TIME=$(echo "$RESULT" | jq -r '.analysis_time // 0')
            
            echo -e "\n=========================================="
            echo -e "${GREEN}ANALYSIS SUMMARY${NC}"
            echo "=========================================="
            echo "IOCTL Handler: $IOCTL_HANDLER"
            echo "IOCTL Codes: $IOCTL_CODES"
            echo "Vulnerabilities: $VULN_COUNT"
            echo "Analysis Time: ${ANALYSIS_TIME}s"
            
            if [ "$VULN_COUNT" -gt 0 ]; then
                echo -e "\n${RED}Vulnerabilities Found:${NC}"
                echo "$RESULT" | jq -r '.vuln[] | "• \(.title): \(.description)"'
            fi
        else
            # Without jq, just print raw JSON
            echo "$RESULT"
        fi
        
        echo -e "\n${GREEN}✓ Done!${NC}"
        exit 0
        
    elif [ "$STATUS" = "failed" ]; then
        ERROR=$(echo "$STATUS_RESPONSE" | jq -r '.error // "Unknown error"' 2>/dev/null)
        echo -e "\n${RED}✗ Analysis failed: $ERROR${NC}"
        exit 1
        
    elif [ "$STATUS" = "running" ] || [ "$STATUS" = "pending" ]; then
        # Show progress indicator
        if [ $(($POLL_COUNT % 5)) -eq 0 ] && [ $POLL_COUNT -gt 0 ]; then
            echo -n "."
        fi
    else
        echo -e "\n${RED}✗ Unknown status: $STATUS${NC}"
        echo "$STATUS_RESPONSE" | $JQ
        exit 1
    fi
    
    POLL_COUNT=$((POLL_COUNT + 1))
done

echo -e "\n${RED}✗ Analysis timed out after ${TIMEOUT}s${NC}"
exit 1