from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import nmap3
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel
import socket
import logging
import threading
import time
import subprocess
import re

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
scan_thread: Optional[threading.Thread] = None
scan_stop_event = threading.Event()

class Node(BaseModel):
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os: Optional[str] = None
    open_ports: List[Dict[str, str]] = []
    last_seen: str
    status: str
    connected_to: List[str] = []  # List of IPs this node is connected to
    gateway: Optional[str] = None  # Gateway IP if this is detected
    hop_distance: Optional[int] = None  # Number of hops from the scanning machine


def get_default_gateway() -> Optional[str]:
    try:
        # Use ipconfig to get the default gateway
        result = subprocess.run(['ipconfig'], capture_output=True, text=True)
        output = result.stdout
        
        # Look for the default gateway in the output
        for line in output.split('\n'):
            if 'Default Gateway' in line:
                match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if match:
                    return match.group(0)
    except Exception as e:
        print(f"Error getting default gateway: {str(e)}")
    return None


def get_local_network_info() -> Dict[str, Dict]:
    """Get information about the local network using ARP"""
    network_info = {}
    try:
        # Use arp -a to get the ARP table
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        output = result.stdout
        
        # Parse the output to get IP-MAC mappings
        for line in output.split('\n'):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f-]+)', line)
            if match:
                ip = match.group(1)
                mac = match.group(2)
                network_info[ip] = {'mac': mac}
    except Exception as e:
        print(f"Error getting ARP table: {str(e)}")
    return network_info


def scan_network():
    global discovered_nodes
    nmap = nmap3.Nmap()
    nmap_scan = nmap3.NmapScanTechniques()

    while not scan_stop_event.is_set():
        try:
            # Step 1: Get default gateway
            gateway_ip = get_default_gateway()
            print(f"Default gateway: {gateway_ip}")

            # Step 2: Fast ping sweep of the entire subnet
            print("Starting fast ping sweep...")
            active_ips = set()
            ping_results = nmap_scan.nmap_ping_scan("192.168.1.0/24")
            
            for ip, data in ping_results.items():
                if isinstance(data, dict) and data.get('state', {}).get('state') != 'down':
                    active_ips.add(ip)
            
            print(f"Found {len(active_ips)} active hosts")

            # Step 3: Get local network information from ARP table
            network_info = get_local_network_info()

            # Step 4: Detailed scan of active hosts
            for ip in active_ips:
                if scan_stop_event.is_set():
                    break

                print(f"Detailed scan of {ip}")
                
                # Get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = None

                # Quick version detection for open ports
                try:
                    version_results = nmap.nmap_version_detection(ip, args="-T4 --version-intensity 5")
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
                except Exception as e:
                    print(f"Error scanning ports for {ip}: {str(e)}")
                    open_ports = []

                # Get OS info (quick scan)
                try:
                    os_results = nmap.nmap_os_detection(ip, args="-T4")
                    os_info = os_results[0]["name"] if os_results else None
                except Exception:
                    os_info = None

                # Get MAC address from network info
                mac_address = network_info.get(ip, {}).get('mac')
                if not mac_address:
                    try:
                        arp_results = nmap.nmap_arp_discovery(ip)
                        mac_address = arp_results[ip]["macaddress"][0]["addr"] if ip in arp_results else None
                    except Exception:
                        mac_address = None

                # Determine network topology
                connected_to = []
                hop_distance = 1  # Default for local network nodes

                # If this is the gateway
                if ip == gateway_ip:
                    connected_to = list(active_ips - {ip})  # Connect to all other nodes
                    hop_distance = 0
                # For other nodes, connect to the gateway if it exists
                elif gateway_ip:
                    connected_to = [gateway_ip]
                    hop_distance = 1

                    # If we have MAC addresses, we can determine direct connections
                    if mac_address and ip in network_info:
                        for other_ip in active_ips:
                            if other_ip != ip and other_ip in network_info:
                                # If we can see the MAC address, it's likely a direct connection
                                connected_to.append(other_ip)

                # Update discovered nodes
                node_info = Node(
                    ip=ip,
                    hostname=hostname,
                    mac_address=mac_address,
                    os=os_info,
                    open_ports=open_ports,
                    last_seen=datetime.now().isoformat(),
                    status="up",
                    connected_to=connected_to,
                    gateway=gateway_ip if ip == gateway_ip else None,
                    hop_distance=hop_distance
                )
                discovered_nodes[ip] = node_info.model_dump()

            # Wait before next scan cycle
            for _ in range(50):  # 5 seconds with frequent checks for stop event
                if scan_stop_event.is_set():
                    break
                time.sleep(0.1)

        except Exception as e:
            print(f"Error during network scan: {str(e)}")
            # Wait before retrying on error
            for _ in range(30):
                if scan_stop_event.is_set():
                    break
                time.sleep(0.1)


@app.post("/start_scan")
async def start_scan():
    global scan_thread
    if not scan_thread or not scan_thread.is_alive():
        scan_stop_event.clear()
        scan_thread = threading.Thread(target=scan_network, daemon=True)
        scan_thread.start()
        return {"message": "Scanning started"}
    return {"message": "Scan already in progress"}


@app.post("/stop_scan")
async def stop_scan():
    global scan_thread
    if scan_thread and scan_thread.is_alive():
        scan_stop_event.set()
        scan_thread.join(timeout=1)  # Wait for thread to finish
    return {"message": "Scanning stopped"}


@app.get("/nodes", response_model=List[Node])
async def get_nodes():
    return list(discovered_nodes.values())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
