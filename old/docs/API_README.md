# IOCTLance REST API

IOCTLance provides a high-performance REST API built with FastAPI for analyzing Windows drivers for vulnerabilities. The API supports asynchronous processing, WebSocket notifications, and batch analysis.

## Features

- **Async Processing**: Non-blocking analysis using background tasks
- **WebSocket Support**: Real-time notifications for analysis progress
- **Batch Analysis**: Analyze multiple drivers in parallel
- **File Upload**: Secure file upload with hash verification
- **Health Monitoring**: Built-in health check endpoints
- **Auto Documentation**: Interactive API docs at `/docs`

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Start the API server
docker-compose up -d

# Check health
curl http://localhost:8080/health

# View logs
docker-compose logs -f
```

### Using Docker

```bash
# Build the image
docker build -f Dockerfile.api -t ioctlance-api:latest .

# Run the container
docker run -d \
  --name ioctlance-api \
  -p 8080:8080 \
  -v $(pwd)/samples:/app/samples:ro \
  ioctlance-api:latest

# Check status
docker logs ioctlance-api
```

### Local Development

```bash
# Install dependencies
uv sync

# Run the API server
uv run uvicorn ioctlance.api.app:app --host 0.0.0.0 --port 8080 --reload
```

## API Endpoints

### General

- `GET /` - API information
- `GET /health` - Health check
- `GET /docs` - Interactive API documentation
- `GET /redoc` - Alternative API documentation

### Analysis

- `POST /upload` - Upload a driver file
- `POST /analyze/{file_hash}` - Start analysis of uploaded driver
- `GET /status/{job_id}` - Get job status
- `GET /result/{job_id}` - Get analysis result
- `POST /batch` - Batch analysis of multiple drivers
- `GET /jobs` - List all jobs
- `DELETE /job/{job_id}` - Delete completed job

### WebSocket

- `WS /ws/{job_id}` - Real-time updates for a job

## Usage Examples

### Upload and Analyze a Driver

```bash
# 1. Upload driver
RESPONSE=$(curl -s -X POST http://localhost:8080/upload \
  -F "file=@driver.sys")
FILE_HASH=$(echo $RESPONSE | jq -r '.file_hash')

# 2. Start analysis
RESPONSE=$(curl -s -X POST http://localhost:8080/analyze/${FILE_HASH} \
  -H "Content-Type: application/json" \
  -d '{"timeout": 120, "complete_mode": false}')
JOB_ID=$(echo $RESPONSE | jq -r '.job_id')

# 3. Check status
curl -s http://localhost:8080/status/${JOB_ID} | jq

# 4. Get result when complete
curl -s http://localhost:8080/result/${JOB_ID} | jq
```

### Batch Analysis

```bash
# Upload multiple drivers first
FILE_HASH1=$(curl -s -X POST http://localhost:8080/upload \
  -F "file=@driver1.sys" | jq -r '.file_hash')
FILE_HASH2=$(curl -s -X POST http://localhost:8080/upload \
  -F "file=@driver2.sys" | jq -r '.file_hash')

# Start batch analysis
curl -s -X POST http://localhost:8080/batch \
  -H "Content-Type: application/json" \
  -d '{
    "file_hashes": ["'$FILE_HASH1'", "'$FILE_HASH2'"],
    "config": {"timeout": 60}
  }' | jq
```

### WebSocket Real-time Updates

```javascript
// JavaScript WebSocket client example
const ws = new WebSocket('ws://localhost:8080/ws/' + jobId);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Update:', data);
  
  if (data.event === 'completed') {
    console.log('Analysis completed!');
    ws.close();
  }
};
```

### Python Client Example

```python
import requests
import json
import time

# API base URL
API_URL = "http://localhost:8080"

# Upload driver
with open("driver.sys", "rb") as f:
    response = requests.post(f"{API_URL}/upload", files={"file": f})
    file_hash = response.json()["file_hash"]

# Start analysis
response = requests.post(
    f"{API_URL}/analyze/{file_hash}",
    json={"timeout": 120, "complete_mode": False}
)
job_id = response.json()["job_id"]

# Poll for completion
while True:
    response = requests.get(f"{API_URL}/status/{job_id}")
    status = response.json()["status"]
    
    if status == "completed":
        # Get result
        response = requests.get(f"{API_URL}/result/{job_id}")
        result = response.json()
        print(f"Found {len(result['vuln'])} vulnerabilities")
        break
    elif status == "failed":
        print("Analysis failed")
        break
    
    time.sleep(2)
```

## Configuration

### Analysis Parameters

When starting an analysis, you can configure:

- `timeout`: Maximum analysis time in seconds (1-3600)
- `ioctl_code`: Specific IOCTL code to test (hex format)
- `complete_mode`: Enable complete mode analysis
- `global_var_size`: Size of .data section to symbolize
- `bound`: Loop bound for analysis
- `length`: Maximum path length

### Docker Environment Variables

- `PYTHONUNBUFFERED=1` - Ensure output is not buffered
- `UV_LINK_MODE=copy` - Avoid hardlink issues in containers

## Performance Tuning

### Production Deployment

For production, use Gunicorn with Uvicorn workers:

```bash
gunicorn ioctlance.api.app:app \
  -w 4 \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8080 \
  --access-logfile - \
  --error-logfile -
```

### Scaling

- Use Redis for job storage instead of in-memory
- Deploy multiple workers behind a load balancer
- Use object storage (S3/MinIO) for uploaded files
- Implement rate limiting for API endpoints

## Security Considerations

1. **File Validation**: Only .sys files under 100MB are accepted
2. **Input Validation**: All inputs are validated using Pydantic models
3. **Resource Limits**: Analysis timeouts prevent resource exhaustion
4. **CORS**: Configure allowed origins for production
5. **Authentication**: Add API key authentication for production

## Monitoring

### Health Check

The `/health` endpoint provides:
- Service status
- IOCTLance version
- Active and completed job counts
- Current timestamp

### Metrics

Monitor these key metrics:
- Analysis completion rate
- Average analysis time
- Vulnerability detection rate
- API response times

## Troubleshooting

### Container won't start
- Check port 8080 is not in use: `lsof -i :8080`
- Verify Docker has enough resources
- Check container logs: `docker logs ioctlance-api`

### Analysis timing out
- Increase timeout parameter
- Check system resources (CPU, memory)
- Review driver complexity

### Upload fails
- Verify file is a valid .sys file
- Check file size < 100MB
- Ensure container has write permissions to upload directory

## Test Script

Use the included test script:

```bash
./test_api.sh
```

This script:
1. Uploads a sample driver
2. Starts analysis
3. Monitors progress
4. Retrieves results
5. Lists all jobs

## API Documentation

Interactive API documentation is available at:
- Swagger UI: http://localhost:8080/docs
- ReDoc: http://localhost:8080/redoc

## License

See main IOCTLance LICENSE file.