#!/usr/bin/env python3
"""
IOCTLance REST API Client using httpx

This example demonstrates how to use the IOCTLance REST API to upload
and analyze Windows drivers using the modern httpx async client.

Requirements:
    pip install httpx
"""

import httpx
import asyncio
import sys
from pathlib import Path
from typing import Optional, Dict, Any


async def analyze_driver(
    driver_path: str,
    api_url: str = "http://localhost:8080",
    timeout: int = 120
) -> Optional[Dict[str, Any]]:
    """
    Upload and analyze a Windows driver using the IOCTLance API.
    
    Args:
        driver_path: Path to the .sys driver file
        api_url: Base URL of the IOCTLance API
        timeout: Analysis timeout in seconds
        
    Returns:
        Analysis results dictionary or None if failed
    """
    driver_path = Path(driver_path)
    if not driver_path.exists():
        print(f"Error: Driver file not found: {driver_path}")
        return None
        
    async with httpx.AsyncClient(base_url=api_url, timeout=30.0) as client:
        # Upload driver
        print(f"Uploading {driver_path.name}...")
        with open(driver_path, "rb") as f:
            response = await client.post("/upload", files={"file": f})
            response.raise_for_status()
            upload_data = response.json()
            file_hash = upload_data["file_hash"]
            print(f"✓ Uploaded successfully (hash: {file_hash[:16]}...)")
        
        # Start analysis
        print(f"Starting analysis (timeout: {timeout}s)...")
        response = await client.post(
            f"/analyze/{file_hash}",
            json={"timeout": timeout, "complete_mode": False}
        )
        response.raise_for_status()
        job_data = response.json()
        job_id = job_data["job_id"]
        print(f"✓ Analysis started (job ID: {job_id[:8]}...)")
        
        # Poll for completion
        print("Waiting for results...")
        max_polls = (timeout + 30) // 2  # Poll every 2 seconds, with buffer
        
        for i in range(max_polls):
            status = await client.get(f"/status/{job_id}")
            status.raise_for_status()
            status_data = status.json()
            
            if status_data["status"] == "completed":
                # Get full results
                result = await client.get(f"/result/{job_id}")
                result.raise_for_status()
                result_data = result.json()
                
                print(f"✓ Analysis completed!")
                print(f"  - IOCTL Handler: {result_data.get('ioctl_handler', {}).get('address', 'Unknown')}")
                print(f"  - IOCTL Codes: {len(result_data.get('ioctl_handler', {}).get('ioctl_codes', []))}")
                print(f"  - Vulnerabilities: {len(result_data.get('vuln', []))}")
                
                # Print vulnerability details
                for vuln in result_data.get('vuln', []):
                    print(f"\n  🔴 {vuln.get('title', 'Unknown')}")
                    print(f"     {vuln.get('description', 'No description')}")
                    if 'eval' in vuln:
                        print(f"     IOCTL: {vuln['eval'].get('IoControlCode', 'Unknown')}")
                
                return result_data
                
            elif status_data["status"] == "failed":
                print(f"✗ Analysis failed: {status_data.get('error', 'Unknown error')}")
                return None
            
            # Show progress dots
            if i % 5 == 0 and i > 0:
                print(".", end="", flush=True)
                
            await asyncio.sleep(2)
        
        print(f"\n✗ Analysis timed out after {timeout}s")
        return None


async def main():
    """Main entry point for the client."""
    if len(sys.argv) < 2:
        print("Usage: python httpx_client.py <driver.sys> [api_url]")
        print("Example: python httpx_client.py samples/RtDashPt.sys")
        sys.exit(1)
    
    driver_path = sys.argv[1]
    api_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8080"
    
    print(f"IOCTLance API Client")
    print(f"API: {api_url}")
    print(f"Driver: {driver_path}")
    print("-" * 50)
    
    try:
        result = await analyze_driver(driver_path, api_url)
        if result:
            print("\n✓ Analysis complete!")
            sys.exit(0)
        else:
            print("\n✗ Analysis failed")
            sys.exit(1)
    except httpx.HTTPError as e:
        print(f"\n✗ HTTP Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())