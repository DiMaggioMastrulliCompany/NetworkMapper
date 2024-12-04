from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import nmap3
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel
import socket
import logging
import multiprocessing
from multiprocessing import Process, Manager, Event
import time

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize process manager and shared data
manager = Manager()
discovered_nodes = manager.dict()
scan_process: Optional[Process] = None
scan_stop_event = Event()

class Node(BaseModel):
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os: Optional[str] = None
    open_ports: List[Dict[str, str]] = []
    last_seen: str
    status: str


def generate_ip_list():
    base_ip = "192.168.1."
    return [f"{base_ip}{i}" for i in range(1, 255)]


def scan_network(discovered_nodes_shared, stop_event):
    nmap = nmap3.Nmap()
    nmap_scan = nmap3.NmapScanTechniques()

    while not stop_event.is_set():
        try:
            # Generate list of IPs to scan
            ip_list = generate_ip_list()

            # Scan each IP individually
            for ip in ip_list:
                if stop_event.is_set():  # Check if scanning was stopped
                    break

                logging.info(f"Scanning {ip}")

                # Perform host discovery using ping scan for single IP
                results = nmap_scan.nmap_ping_scan(ip)

                # Skip if host is down
                if ip in results and isinstance(results[ip], dict):
                    state = results[ip].get('state', {}).get('state', 'down')
                    if state == 'down':
                        continue

                # Get version detection for the host
                version_results = nmap.nmap_version_detection(ip)

                # Try OS detection (requires root/admin privileges) TODO admin
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

                # Get mac address
                try:
                    mac_address = nmap.nmap_arp_discovery(ip)
                    mac_address = mac_address[ip]["macaddress"][0]["addr"]
                except Exception:
                    mac_address = None

                # Update discovered nodes immediately for this IP
                node_info = Node(
                    ip=ip,
                    hostname=hostname,
                    mac_address=mac_address,
                    os=os_info,
                    open_ports=open_ports,
                    last_seen=datetime.now().isoformat(),
                    status="up"
                )
                discovered_nodes_shared[ip] = node_info.dict()

        except Exception as e:
            print(f"Error during network scan: {str(e)}")
            if not stop_event.is_set():
                # Wait before retrying on error
                for _ in range(50):  # Split the sleep into smaller chunks
                    if stop_event.is_set():
                        break
                    time.sleep(0.1)


@app.post("/start_scan")
async def start_scan():
    global scan_process
    if not scan_process or not scan_process.is_alive():
        scan_stop_event.clear()
        scan_process = Process(
            target=scan_network,
            args=(discovered_nodes, scan_stop_event),
            daemon=True
        )
        scan_process.start()
        return {"message": "Scanning started"}
    return {"message": "Scan already in progress"}


@app.post("/stop_scan")
async def stop_scan():
    global scan_process
    if scan_process and scan_process.is_alive():
        scan_stop_event.set()
        scan_process.join(timeout=1)
        if scan_process.is_alive():
            scan_process.terminate()
    return {"message": "Scanning stopped"}


@app.get("/nodes", response_model=List[Node])
async def get_nodes():
    return list(discovered_nodes.values())


if __name__ == "__main__":
    # Set start method for Windows
    multiprocessing.set_start_method('spawn')
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
