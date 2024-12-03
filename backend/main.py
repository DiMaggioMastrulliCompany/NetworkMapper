from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import nmap3
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel
import socket
import subprocess
from collections import defaultdict

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global storage for discovered nodes
discovered_nodes: Dict[str, dict] = {}
scanning = False

class Node(BaseModel):
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os: Optional[str] = None
    open_ports: List[Dict[str, str]] = []
    last_seen: str
    status: str

async def scan_network():
    global scanning, discovered_nodes
    nmap = nmap3.Nmap()
    nmap_scan = nmap3.NmapScanTechniques()

    while scanning:
        try:
            # Perform host discovery using ping scan
            results = nmap_scan.nmap_ping_scan("192.168.1.0/24")

            # Process each host
            for ip in results:
                if ip == "stats" or ip == "runtime" or ip == "task_results":  # Skip summary entries
                    continue

                # Get version detection for the host
                version_results = nmap.nmap_version_detection(ip)

                # Try OS detection (requires root/admin privileges)
                try:
                    os_results = nmap.nmap_os_detection(ip)
                    os_info = os_results[0]["name"] if os_results else None
                except Exception:
                    os_info = None

                # Process ports and services
                open_ports = []
                for port_info in version_results:
                    if "service" in port_info:
                        service = port_info["service"]
                        port_data = {
                            "port": port_info["port"],
                            "service": service.get("name", "unknown"),
                            "version": service.get("version", "unknown"),
                            "product": service.get("product", "unknown")
                        }
                        open_ports.append(port_data)

                # Get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = None

                # Update discovered nodes
                node_info = Node(
                    ip=ip,
                    hostname=hostname,
                    os=os_info,
                    open_ports=open_ports,
                    last_seen=datetime.now().isoformat(),
                    status="up"
                )
                discovered_nodes[ip] = node_info.model_dump()

            await asyncio.sleep(60)  # Scan every minute

        except Exception as e:
            print(f"Error during network scan: {str(e)}")
            await asyncio.sleep(5)  # Wait before retrying on error

@app.get("/start_scan")
async def start_scan(background_tasks: BackgroundTasks):
    global scanning
    if not scanning:
        scanning = True
        background_tasks.add_task(scan_network)
        return {"message": "Network scanning started"}
    return {"message": "Scanning already in progress"}

@app.get("/stop_scan")
async def stop_scan():
    global scanning
    scanning = False
    return {"message": "Network scanning stopped"}

@app.get("/nodes")
async def get_nodes():
    return list(discovered_nodes.values())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
