"""FastAPI application for IOCTLance vulnerability scanner."""

import asyncio
import hashlib
import tempfile
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles
from fastapi import (
    BackgroundTasks,
    FastAPI,
    File,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from ..core.analysis_context import AnalysisConfig, AnalysisContext
from ..core.driver_analyzer import DriverAnalyzer
from ..models import AnalysisResult
from ..__version__ import __version__


# Data models for API
class AnalysisRequest(BaseModel):
    """Request model for driver analysis."""

    timeout: int = Field(default=120, ge=1, le=3600, description="Analysis timeout in seconds")
    ioctl_code: str | None = Field(None, description="Specific IOCTL code to test (hex format)")
    complete_mode: bool = Field(False, description="Enable complete mode analysis")
    global_var_size: int = Field(default=0, ge=0, description="Size of .data section to symbolize")
    bound: int | None = Field(None, ge=0, description="Loop bound for analysis")
    length: int | None = Field(None, ge=0, description="Maximum path length")


class AnalysisStatus(BaseModel):
    """Status model for analysis job."""

    job_id: str = Field(..., description="Unique job identifier")
    status: str = Field(..., description="Job status (pending/running/completed/failed)")
    driver_name: str = Field(..., description="Name of the driver being analyzed")
    started_at: datetime | None = Field(None, description="When analysis started")
    completed_at: datetime | None = Field(None, description="When analysis completed")
    result: AnalysisResult | None = Field(None, description="Analysis result if completed")
    error: str | None = Field(None, description="Error message if failed")
    progress: dict[str, Any] | None = Field(None, description="Progress information")


class HealthStatus(BaseModel):
    """Health check response model."""

    status: str = Field(..., description="Service status")
    version: str = Field(..., description="IOCTLance version")
    timestamp: datetime = Field(..., description="Current timestamp")
    active_jobs: int = Field(0, description="Number of active analysis jobs")
    completed_jobs: int = Field(0, description="Number of completed jobs")


class BatchAnalysisRequest(BaseModel):
    """Request model for batch analysis."""

    file_hashes: list[str] = Field(..., description="List of file hashes to analyze")
    config: AnalysisRequest = Field(default_factory=AnalysisRequest, description="Analysis configuration")


# In-memory job storage (use Redis/database in production)
analysis_jobs: dict[str, AnalysisStatus] = {}
websocket_connections: dict[str, list[WebSocket]] = {}
uploaded_files: dict[str, Path] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    print(f"Starting IOCTLance API v{__version__}")
    # Create temp directory for uploads
    app.state.upload_dir = Path(tempfile.mkdtemp(prefix="ioctlance_"))
    yield
    # Shutdown
    print("Shutting down IOCTLance API")
    # Cleanup temp files
    if hasattr(app.state, "upload_dir") and app.state.upload_dir.exists():
        import shutil

        shutil.rmtree(app.state.upload_dir)


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="IOCTLance API",
        description="Windows Driver Vulnerability Scanner API",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Add CORS middleware for web clients
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return app


# Create app instance
app = create_app()


def get_app() -> FastAPI:
    """Get the FastAPI application instance."""
    return app


# Utility functions
async def save_upload_file(upload_file: UploadFile, destination: Path) -> None:
    """Save uploaded file to disk asynchronously."""
    async with aiofiles.open(destination, "wb") as f:
        while chunk := await upload_file.read(8192):  # Read in 8KB chunks
            await f.write(chunk)


def calculate_file_hash(file_path: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


async def notify_websocket_clients(job_id: str, message: dict[str, Any]) -> None:
    """Notify WebSocket clients about job updates."""
    if job_id in websocket_connections:
        disconnected = []
        for websocket in websocket_connections[job_id]:
            try:
                await websocket.send_json(message)
            except:
                disconnected.append(websocket)
        # Remove disconnected clients
        for ws in disconnected:
            websocket_connections[job_id].remove(ws)


async def run_analysis(job_id: str, driver_path: Path, config: AnalysisRequest) -> None:
    """Run driver analysis as a background task."""
    job = analysis_jobs[job_id]
    job.status = "running"
    job.started_at = datetime.now()

    try:
        # Notify WebSocket clients
        await notify_websocket_clients(
            job_id, {"event": "started", "job_id": job_id, "timestamp": job.started_at.isoformat()}
        )

        # Create analysis configuration
        analysis_config = AnalysisConfig(
            timeout=config.timeout,
            target_ioctl=config.ioctl_code,
            global_var_size=config.global_var_size,
            complete_mode=config.complete_mode,
            bound=config.bound,
            length=config.length,
        )

        # Create context and analyzer
        context = AnalysisContext.create_for_driver(driver_path, analysis_config)
        analyzer = DriverAnalyzer(context)

        # Run analysis in executor to avoid blocking event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, analyzer.analyze)

        # Update job with result
        job.status = "completed"
        job.completed_at = datetime.now()
        job.result = result

        # Notify WebSocket clients
        await notify_websocket_clients(
            job_id,
            {
                "event": "completed",
                "job_id": job_id,
                "timestamp": job.completed_at.isoformat(),
                "vulnerabilities_found": len(result.vuln),
            },
        )

    except Exception as e:
        job.status = "failed"
        job.completed_at = datetime.now()
        job.error = str(e)

        # Notify WebSocket clients
        await notify_websocket_clients(
            job_id, {"event": "failed", "job_id": job_id, "timestamp": job.completed_at.isoformat(), "error": str(e)}
        )


# API Endpoints
@app.get("/", tags=["General"])
async def root():
    """Root endpoint."""
    return {
        "name": "IOCTLance API",
        "version": __version__,
        "description": "Windows Driver Vulnerability Scanner",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "upload": "/upload",
            "analyze": "/analyze/{file_hash}",
            "status": "/status/{job_id}",
            "batch": "/batch",
        },
    }


@app.get("/health", response_model=HealthStatus, tags=["General"])
async def health_check():
    """Health check endpoint."""
    active_jobs = sum(1 for job in analysis_jobs.values() if job.status == "running")
    completed_jobs = sum(1 for job in analysis_jobs.values() if job.status == "completed")

    return HealthStatus(
        status="healthy",
        version=__version__,
        timestamp=datetime.now(),
        active_jobs=active_jobs,
        completed_jobs=completed_jobs,
    )


@app.post("/upload", tags=["Analysis"])
async def upload_driver(file: UploadFile = File(..., description="Windows driver file (.sys)")):
    """Upload a driver file for analysis."""
    # Validate file extension
    if not file.filename.endswith(".sys"):
        raise HTTPException(status_code=400, detail="Only .sys files are supported")

    # Validate file size (max 100MB)
    if file.size and file.size > 100 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds 100MB limit")

    # Save file to temp directory
    file_path = app.state.upload_dir / f"{uuid.uuid4()}_{file.filename}"
    await save_upload_file(file, file_path)

    # Calculate file hash
    file_hash = calculate_file_hash(file_path)

    # Store file path
    uploaded_files[file_hash] = file_path

    return {
        "file_hash": file_hash,
        "filename": file.filename,
        "size": file_path.stat().st_size,
        "message": "File uploaded successfully",
    }


@app.post("/analyze/{file_hash}", response_model=AnalysisStatus, tags=["Analysis"])
async def analyze_driver(
    file_hash: str, background_tasks: BackgroundTasks, request: AnalysisRequest = AnalysisRequest()
):
    """Start analysis of an uploaded driver."""
    # Check if file exists
    if file_hash not in uploaded_files:
        raise HTTPException(status_code=404, detail="File not found. Please upload first.")

    driver_path = uploaded_files[file_hash]
    if not driver_path.exists():
        raise HTTPException(status_code=404, detail="File no longer exists")

    # Create job
    job_id = str(uuid.uuid4())
    job = AnalysisStatus(
        job_id=job_id, status="pending", driver_name=driver_path.name, started_at=None, completed_at=None
    )
    analysis_jobs[job_id] = job

    # Start background analysis
    background_tasks.add_task(run_analysis, job_id, driver_path, request)

    return job


@app.get("/status/{job_id}", response_model=AnalysisStatus, tags=["Analysis"])
async def get_analysis_status(job_id: str):
    """Get the status of an analysis job."""
    if job_id not in analysis_jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    return analysis_jobs[job_id]


@app.get("/result/{job_id}", tags=["Analysis"])
async def get_analysis_result(job_id: str, format: str = Query("json", enum=["json", "stream"])):
    """Get the result of a completed analysis job."""
    if job_id not in analysis_jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = analysis_jobs[job_id]

    if job.status != "completed":
        raise HTTPException(status_code=400, detail=f"Job is {job.status}, not completed")

    if not job.result:
        raise HTTPException(status_code=500, detail="Result not available")

    if format == "stream":
        # Stream the result for large responses
        async def generate():
            result_json = job.result.model_dump_json(indent=2)
            chunk_size = 8192
            for i in range(0, len(result_json), chunk_size):
                yield result_json[i : i + chunk_size].encode()

        return StreamingResponse(generate(), media_type="application/json")
    else:
        # Use model_dump with mode='json' for proper datetime serialization
        return JSONResponse(content=job.result.model_dump(mode="json"))


@app.post("/batch", tags=["Analysis"])
async def batch_analyze(batch_request: BatchAnalysisRequest, background_tasks: BackgroundTasks):
    """Start batch analysis of multiple uploaded drivers."""
    job_ids = []

    for file_hash in batch_request.file_hashes:
        if file_hash not in uploaded_files:
            continue  # Skip missing files

        driver_path = uploaded_files[file_hash]
        if not driver_path.exists():
            continue

        # Create job for each file
        job_id = str(uuid.uuid4())
        job = AnalysisStatus(
            job_id=job_id, status="pending", driver_name=driver_path.name, started_at=None, completed_at=None
        )
        analysis_jobs[job_id] = job
        job_ids.append(job_id)

        # Start background analysis
        background_tasks.add_task(run_analysis, job_id, driver_path, batch_request.config)

    return {"message": f"Started {len(job_ids)} analysis jobs", "job_ids": job_ids}


@app.websocket("/ws/{job_id}")
async def websocket_endpoint(websocket: WebSocket, job_id: str):
    """WebSocket endpoint for real-time job updates."""
    await websocket.accept()

    # Check if job exists
    if job_id not in analysis_jobs:
        await websocket.send_json({"error": "Job not found"})
        await websocket.close()
        return

    # Add to connection list
    if job_id not in websocket_connections:
        websocket_connections[job_id] = []
    websocket_connections[job_id].append(websocket)

    try:
        # Send initial status
        job = analysis_jobs[job_id]
        await websocket.send_json(
            {
                "event": "connected",
                "job_id": job_id,
                "status": job.status,
                "driver_name": job.driver_name,
            }
        )

        # Keep connection alive
        while True:
            await asyncio.sleep(1)
            # Check if job is done
            if job.status in ["completed", "failed"]:
                await asyncio.sleep(5)  # Give time for final message
                break

    except WebSocketDisconnect:
        # Remove from connection list
        if job_id in websocket_connections:
            websocket_connections[job_id].remove(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        if job_id in websocket_connections and websocket in websocket_connections[job_id]:
            websocket_connections[job_id].remove(websocket)


@app.delete("/job/{job_id}", tags=["Analysis"])
async def delete_job(job_id: str):
    """Delete a completed job and its results."""
    if job_id not in analysis_jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = analysis_jobs[job_id]
    if job.status == "running":
        raise HTTPException(status_code=400, detail="Cannot delete running job")

    del analysis_jobs[job_id]
    return {"message": "Job deleted successfully"}


@app.get("/jobs", tags=["Analysis"])
async def list_jobs(
    status_filter: str | None = Query(None, enum=["pending", "running", "completed", "failed"]),
    limit: int = Query(100, ge=1, le=1000),
):
    """List all analysis jobs."""
    jobs = list(analysis_jobs.values())

    if status_filter:
        jobs = [job for job in jobs if job.status == status_filter]

    # Sort by started_at descending
    jobs.sort(key=lambda x: x.started_at or datetime.min, reverse=True)

    return {"total": len(jobs), "jobs": jobs[:limit]}


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions."""
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions."""
    return JSONResponse(status_code=500, content={"error": "Internal server error", "detail": str(exc)})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("ioctlance.api.app:app", host="0.0.0.0", port=8080, reload=True)
