# IOCTLance API Client Examples

This directory contains example clients for interacting with the IOCTLance REST API.

## Available Clients

### 1. Python httpx Client (`httpx_client.py`)

A modern async Python client using httpx for REST API interactions.

**Features:**
- Async/await support for efficient I/O
- Progress indicators
- Comprehensive error handling
- Detailed vulnerability reporting

**Usage:**
```bash
# Install dependencies
pip install httpx

# Run analysis
python httpx_client.py samples/RtDashPt.sys

# With custom API URL
python httpx_client.py driver.sys http://remote-api:8080
```

### 2. WebSocket Client (`websocket_client.py`)

Real-time monitoring of analysis progress using WebSocket connections.

**Features:**
- Live progress updates
- Real-time vulnerability detection notifications
- Event-based architecture
- Detailed status reporting with emojis

**Usage:**
```bash
# Install dependencies
pip install httpx websockets

# Run with real-time monitoring
python websocket_client.py samples/RtDashPt.sys

# With custom API URL
python websocket_client.py driver.sys http://remote-api:8080
```

### 3. Bash/curl Client (`curl_client.sh`)

Shell script for environments where Python is not available.

**Features:**
- Pure bash/curl implementation
- Optional jq support for pretty output
- Colored terminal output
- Progress indicators

**Usage:**
```bash
# Make executable
chmod +x curl_client.sh

# Run analysis
./curl_client.sh samples/RtDashPt.sys

# With custom timeout (seconds)
./curl_client.sh samples/RtDashPt.sys 300

# With custom API URL (via environment variable)
API_URL=http://remote-api:8080 ./curl_client.sh driver.sys
```

## API Configuration

All clients support configuring the API endpoint:

- **Default**: `http://localhost:8080`
- **Docker**: Use the container name or IP
- **Remote**: Specify the full URL including port

## Running the API Server

Before using these clients, ensure the IOCTLance API is running:

### Using Docker Compose (Recommended)
```bash
docker compose up -d
```

### Using Docker
```bash
docker build -f Dockerfile.api -t ioctlance-api .
docker run -d -p 8080:8080 -v $(pwd)/samples:/app/samples:ro ioctlance-api
```

### Local Development
```bash
uv run uvicorn ioctlance.api.app:app --host 0.0.0.0 --port 8080
```

## Output Examples

### httpx Client Output
```
IOCTLance API Client
API: http://localhost:8080
Driver: samples/RtDashPt.sys
--------------------------------------------------
Uploading RtDashPt.sys...
✓ Uploaded successfully (hash: 762141766c880b17...)
Starting analysis (timeout: 120s)...
✓ Analysis started (job ID: b499b299...)
Waiting for results...
✓ Analysis completed!
  - IOCTL Handler: 0x140007080
  - IOCTL Codes: 5
  - Vulnerabilities: 2

  🔴 Null Pointer Dereference
     State may dereference null pointer leading to crash
     IOCTL: 0x12c8c4
```

### WebSocket Client Output
```
IOCTLance WebSocket Client
==================================================
API: http://localhost:8080
Driver: samples/RtDashPt.sys
--------------------------------------------------

📤 Uploading RtDashPt.sys...
✓ Upload complete (hash: 762141766c880b17...)
🔍 Starting analysis...
✓ Job started (ID: ac03245d...)
📡 Connecting to WebSocket...
✓ Connected! Monitoring analysis...

🔗 WebSocket connection established
▶️  Analysis started
🔴 Found vulnerability: Null Pointer Dereference [HIGH]
⏳ Progress: hunting_vulnerabilities (50%)
🔴 Found vulnerability: Buffer Overflow [CRITICAL]

==================================================
✅ ANALYSIS COMPLETED
==================================================
Time: 5.23 seconds
Vulnerabilities found: 2
```

### curl Client Output
```
==========================================
IOCTLance API Client (curl)
==========================================
API: http://localhost:8080
Driver: samples/RtDashPt.sys
Timeout: 120s
------------------------------------------

Checking API health...
✓ API is healthy

Uploading driver...
✓ Upload successful
  File hash: 762141766c880b17...

Starting analysis...
✓ Analysis started
  Job ID: b499b299...

Waiting for results...
✓ Analysis completed!

==========================================
ANALYSIS SUMMARY
==========================================
IOCTL Handler: 0x140007080
IOCTL Codes: 5
Vulnerabilities: 2
Analysis Time: 5.2s

Vulnerabilities Found:
• Null Pointer Dereference: State may dereference null pointer
• Buffer Overflow: Unconstrained state with symbolic PC
```

## Error Handling

All clients include comprehensive error handling for:
- Connection failures
- Upload errors
- Analysis timeouts
- API errors
- Invalid responses

## Security Notes

⚠️ **The API currently has no authentication**. For production use:
1. Implement API key or JWT authentication
2. Use HTTPS/TLS for all connections
3. Run behind a reverse proxy (nginx, Caddy)
4. Implement rate limiting
5. Validate and sanitize all inputs

## Requirements

- **Python clients**: Python 3.8+ with httpx/websockets
- **Bash client**: curl (jq optional but recommended)
- **API Server**: Docker or Python 3.13+ with uv

## License

See main IOCTLance LICENSE file.