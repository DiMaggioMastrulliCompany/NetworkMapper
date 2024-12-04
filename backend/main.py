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
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os: Optional[str] = None
    open_ports: List[Dict[str, int | str]] = []
    last_seen: str
    status: str
    # Topology related fields
    connected_to: List[str] = []  # List of IPs this node is connected to
    gateway: Optional[str] = None  # Gateway IP if this is detected
    hop_distance: Optional[int] = None  # Number of hops from the scanning machine


def generate_ip_list():
    base_ip = "192.168.1."
    return [f"{base_ip}{i}" for i in range(1, 255)]


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
    nm = nmap.PortScanner()

    while not scan_stop_event.is_set():
        try:
            # Step 1: Fast ping sweep of the entire subnet
            print("Starting fast ping sweep...")
            active_ips = set()
            nm.scan(hosts="192.168.1.0/24", arguments="-sn")

            for ip in nm.all_hosts():
                if nm[ip].state() != 'down':
                    active_ips.add(ip)

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

            # Step 3: Detailed scan of active hosts
            for ip in active_ips:
                if scan_stop_event.is_set():
                    break

                print(f"Detailed scan of {ip}")

                # Get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = None

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

                # Get OS info
                nm.scan(ip, arguments="-O")
                os_info = None
                if ip in nm.all_hosts() and 'osmatch' in nm[ip]:
                    if len(nm[ip]['osmatch']) > 0:
                        os_info = nm[ip]['osmatch'][0].get('name')

                # Get MAC address
                nm.scan(ip, arguments="-sn -PR")
                mac_address = None
                if ip in nm.all_hosts() and 'addresses' in nm[ip]:
                    mac_address = nm[ip]['addresses'].get('mac')

                # Determine connections based on topology
                connected_to = []
                hop_distance = None
                gateway = None

                if ip in topology_map:
                    path = topology_map[ip]['path']
                    hop_distance = topology_map[ip]['hop_distance']

                    # First hop after local network is typically the gateway
                    if len(path) > 0:
                        gateway = path[0]

                    # Add connections based on network path
                    if len(path) > 1:
                        connected_to.extend(path[:-1])  # Connect to all hops except itself

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
                    gateway=gateway,
                    hop_distance=hop_distance
                )
                discovered_nodes[ip] = node_info.model_dump()  # .dict() is deprecated

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
