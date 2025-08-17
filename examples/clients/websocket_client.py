#!/usr/bin/env python3
"""
IOCTLance WebSocket Client

This example demonstrates real-time monitoring of driver analysis
using WebSocket connections.

Requirements:
    pip install httpx websockets
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import httpx
import websockets


async def analyze_with_websocket(
    driver_path: str,
    api_url: str = "http://localhost:8080",
    timeout: int = 120
) -> Optional[dict]:
    """
    Analyze a driver and monitor progress via WebSocket.
    
    Args:
        driver_path: Path to the .sys driver file
        api_url: Base URL of the IOCTLance API
        timeout: Analysis timeout in seconds
        
    Returns:
        Analysis results or None if failed
    """
    driver_path = Path(driver_path)
    if not driver_path.exists():
        print(f"Error: Driver file not found: {driver_path}")
        return None
    
    # Convert HTTP URL to WebSocket URL
    ws_url = api_url.replace("http://", "ws://").replace("https://", "wss://")
    
    async with httpx.AsyncClient(base_url=api_url) as client:
        # Upload driver
        print(f"📤 Uploading {driver_path.name}...")
        with open(driver_path, "rb") as f:
            response = await client.post("/upload", files={"file": f})
            response.raise_for_status()
            file_hash = response.json()["file_hash"]
            print(f"✓ Upload complete (hash: {file_hash[:16]}...)")
        
        # Start analysis
        print(f"🔍 Starting analysis...")
        response = await client.post(
            f"/analyze/{file_hash}",
            json={"timeout": timeout}
        )
        response.raise_for_status()
        job_id = response.json()["job_id"]
        print(f"✓ Job started (ID: {job_id[:8]}...)")
        
        # Connect to WebSocket for real-time updates
        ws_uri = f"{ws_url}/ws/{job_id}"
        print(f"📡 Connecting to WebSocket...")
        
        try:
            async with websockets.connect(ws_uri) as websocket:
                print("✓ Connected! Monitoring analysis...\n")
                
                while True:
                    try:
                        # Set a timeout for receiving messages
                        message = await asyncio.wait_for(
                            websocket.recv(),
                            timeout=timeout + 30
                        )
                        data = json.loads(message)
                        event = data.get("event", "unknown")
                        
                        # Handle different event types
                        if event == "connected":
                            print("🔗 WebSocket connection established")
                            
                        elif event == "started":
                            print("▶️  Analysis started")
                            
                        elif event == "progress":
                            progress = data.get("progress", {})
                            if isinstance(progress, dict):
                                stage = progress.get("stage", "unknown")
                                percent = progress.get("percent", 0)
                                print(f"⏳ Progress: {stage} ({percent}%)")
                            else:
                                print(f"⏳ Progress: {progress}")
                                
                        elif event == "vulnerability":
                            vuln = data.get("vulnerability", {})
                            title = vuln.get("title", "Unknown")
                            severity = vuln.get("others", {}).get("severity", "UNKNOWN")
                            print(f"🔴 Found vulnerability: {title} [{severity}]")
                            
                        elif event == "completed":
                            result = data.get("result", {})
                            vulns = result.get("vuln", [])
                            analysis_time = result.get("analysis_time", 0)
                            
                            print("\n" + "="*50)
                            print("✅ ANALYSIS COMPLETED")
                            print("="*50)
                            print(f"Time: {analysis_time:.2f} seconds")
                            print(f"Vulnerabilities found: {len(vulns)}")
                            
                            if vulns:
                                print("\n📋 Vulnerability Summary:")
                                for i, vuln in enumerate(vulns, 1):
                                    print(f"\n  {i}. {vuln.get('title', 'Unknown')}")
                                    print(f"     {vuln.get('description', '')}")
                                    if "eval" in vuln:
                                        ioctl = vuln["eval"].get("IoControlCode", "Unknown")
                                        print(f"     IOCTL: {ioctl}")
                            
                            return result
                            
                        elif event == "failed":
                            error = data.get("error", "Unknown error")
                            print(f"\n❌ Analysis failed: {error}")
                            return None
                            
                        elif event == "error":
                            error = data.get("message", "Unknown error")
                            print(f"⚠️  Error: {error}")
                            
                        else:
                            print(f"📨 Event: {event}")
                            if "message" in data:
                                print(f"   Message: {data['message']}")
                                
                    except asyncio.TimeoutError:
                        print(f"\n⏱️  Timeout waiting for WebSocket message")
                        return None
                        
        except websockets.exceptions.WebSocketException as e:
            print(f"\n❌ WebSocket error: {e}")
            return None
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            return None


async def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python websocket_client.py <driver.sys> [api_url]")
        print("Example: python websocket_client.py samples/RtDashPt.sys")
        sys.exit(1)
    
    driver_path = sys.argv[1]
    api_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8080"
    
    print("="*50)
    print("IOCTLance WebSocket Client")
    print("="*50)
    print(f"API: {api_url}")
    print(f"Driver: {driver_path}")
    print("-"*50 + "\n")
    
    try:
        result = await analyze_with_websocket(driver_path, api_url)
        if result:
            sys.exit(0)
        else:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⛔ Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())