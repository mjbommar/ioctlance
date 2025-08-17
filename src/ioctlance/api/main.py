"""Main entry point for running the FastAPI server."""

import uvicorn


def main():
    """Run the FastAPI application with Uvicorn."""
    uvicorn.run(
        "ioctlance.api.app:app",
        host="0.0.0.0",
        port=8080,
        # Use reload only in development
        reload=False,
        # Use multiple workers for production
        workers=1,
        # Enable access logs
        access_log=True,
        # Use uvloop for better performance
        loop="uvloop",
        # HTTP/2 support
        http="h11",
    )


if __name__ == "__main__":
    main()