import socket
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

import nmap
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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
    mac_address: str = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    open_ports: List[Dict[str, int | str]] = []
    last_seen: str
    status: str
    # Topology related fields
    connected_to: List[str] = []  # List of IPs this node is connected to
    gateway: Optional[str] = None  # Gateway IP if this is detected
    hop_distance: Optional[int] = None  # Number of hops from the scanning machine

    def update_topology(self, path: List[str]) -> None:
        """Update topology-related information"""
        if path:
            self.hop_distance = len(path)
            self.gateway = path[0] if path else None
            self.connected_to = path[:-1] if len(path) > 1 else []

    def update_ports(self, ports_data: List[Dict[str, str | int]]) -> None:
        """Update port information"""
        self.open_ports = ports_data

    def update_basic_info(self, hostname: Optional[str] = None,
                         mac_address: Optional[str] = None,
                         os: Optional[str] = None) -> None:
        """Update basic node information"""
        if hostname is not None:
            self.hostname = hostname
        if mac_address is not None:
            self.mac_address = mac_address
        if os is not None:
            self.os = os

    def touch(self) -> None:
        """Update last seen timestamp"""
        self.last_seen = datetime.now().isoformat()

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses"""
        return self.model_dump()


def get_traceroute(ip: str) -> List[str]:
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-n -sn -PE --traceroute')
        if 'trace' in nm[ip] and 'hops' in nm[ip]['trace']:
            return [hop.get('ipaddr', '') for hop in nm[ip]['trace']['hops'] if hop.get('ipaddr')]
    except Exception as e:
        print(f"Traceroute error for {ip}: {str(e)}")
    return []


def scan_network():
    global discovered_nodes

    while not scan_stop_event.is_set():
        try:
            # Step 1: Fast ping sweep of the entire subnet
            nm = nmap.PortScanner()
            print("Starting fast ping sweep...")
            active_ips = set()

            # Initial scan with MAC address detection
            nm.scan(hosts="192.168.1.0/24", arguments="-sn")

            # Process discovered hosts
            for ip in nm.all_hosts():
                if nm[ip].state() != 'down':
                    active_ips.add(ip)
                    if ip not in discovered_nodes:
                        # Get MAC address from initial scan
                        mac = "unknown"
                        if 'addresses' in nm[ip]:
                            mac = nm[ip]['addresses'].get('mac', "unknown")

                        # Add basic node info immediately
                        node = Node(
                            ip=ip,
                            mac_address=mac,
                            last_seen=datetime.now().isoformat(),
                            status="up"
                        )
                        discovered_nodes[ip] = node.to_dict()

            print(f"Found {len(active_ips)} active hosts")

            # Step 2: Topology discovery using traceroute
            topology_map = {}
            for ip in active_ips:
                if scan_stop_event.is_set():
                    break

                hops = get_traceroute(ip)
                if hops:
                    topology_map[ip] = {
                        'path': hops,
                        'hop_distance': len(hops)
                    }
                    # Update node with topology information
                    if ip in discovered_nodes:
                        node = Node(**discovered_nodes[ip])
                        node.update_topology(hops)
                        discovered_nodes[ip] = node.to_dict()

            # Step 3: Detailed scan of active hosts
            for ip in active_ips:
                if scan_stop_event.is_set():
                    break

                print(f"Detailed scan of {ip}")
                node = Node(**discovered_nodes[ip])

                # Get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    node.update_basic_info(hostname=hostname)
                except socket.herror:
                    pass

                # Version detection scan
                nm.scan(ip, arguments="-sV -T4 --version-intensity 5")

                # Process ports and services
                open_ports = []
                if ip in nm.all_hosts():
                    for proto in nm[ip].all_protocols():
                        ports = nm[ip][proto].keys()
                        for port in ports:
                            service = nm[ip][proto][port]
                            port_data = {
                                "port": port,
                                "service": service.get("name", "unknown"),
                                "version": service.get("version", "unknown"),
                                "product": service.get("product", "unknown")
                            }
                            open_ports.append(port_data)
                node.update_ports(open_ports)

                # Get OS info
                nm.scan(ip, arguments="-O")
                if ip in nm.all_hosts() and 'osmatch' in nm[ip]:
                    if len(nm[ip]['osmatch']) > 0:
                        node.update_basic_info(os=nm[ip]['osmatch'][0].get('name'))

                # Update last seen timestamp
                node.touch()
                discovered_nodes[ip] = node.to_dict()

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
    return [Node(**node) for node in discovered_nodes.values()]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
