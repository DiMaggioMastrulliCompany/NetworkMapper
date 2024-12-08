import socket
import threading
import time
from datetime import datetime
from functools import lru_cache
from typing import List, Optional

import psutil
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from model.hop import Hop
from model.node import Node
from model.nodes import Nodes
from nmap_wrapper import NmapWrapper as PortScanner

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@lru_cache(maxsize=1)
def get_lan_ip() -> str:
    """Get the LAN IP address of the current machine"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


def get_localhost_mac():
    try:
        # Find the default gateway to identify the active interface
        gateways = psutil.net_if_stats()
        default_iface = None
        for iface, stats in gateways.items():
            if stats.isup:  # Only consider interfaces that are UP
                default_iface = iface
                break

        if not default_iface:
            raise Exception("No active network interface found.")

        # Get MAC address for the active interface
        interfaces = psutil.net_if_addrs()
        for iface, addrs in interfaces.items():
            if iface == default_iface:
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:
                        return addr.address

        raise Exception("MAC address not found for active interface.")

    except Exception as e:
        return f"Error: {str(e)}"


def get_traceroute(ip: str) -> List[str]:
    try:
        nm = PortScanner()
        nm.scan(ip, arguments='-n -sn -PE --traceroute')
        if 'trace' in nm[ip] and 'hops' in nm[ip]['trace']:
            return [hop.get('ipaddr', '') for hop in nm[ip]['trace']['hops'] if hop.get('ipaddr')]
    except Exception as e:
        print(f"Traceroute error for {ip}: {str(e)}")
    return []


def scan_network():
    while not scan_stop_event.is_set():
        try:
            # Step 1: Fast ping sweep of the entire subnet
            nm = PortScanner()
            print("Starting fast ping sweep...")
            active_ips = set()

            # Initial scan with MAC address detection and traceroute
            nm.scan(hosts="192.168.1.0/24", arguments="-sn --traceroute")

            # Process discovered hosts
            for ip in nm.all_hosts():
                if nm[ip].state() != 'down':
                    active_ips.add(ip)
                    if not nodes.contains_ip(ip):
                        # Get MAC address from initial scan
                        mac = "unknown"
                        if 'addresses' in nm[ip]:
                            mac = nm[ip]['addresses'].get('mac', "unknown")

                        # Create new node
                        node = Node(ip=ip, mac_address=mac, status="up", last_seen=datetime.now().isoformat())
                        nodes.add_node(node)

                    # Process traceroute data if available
                    if 'trace' in nm[ip]:
                        trace_path: List[Hop] = []
                        trace_data = nm[ip]['trace']

                        # Process trace data (list of hops)
                        if isinstance(trace_data, list):
                            hops: List[Hop] = []
                            for hop in trace_data:
                                hops.append(Hop.from_nmap_hop(hop))

                            nodes.add_hop_list(ip, hops)

            print(f"Found {len(active_ips)} active hosts")

            # Step 3: Detailed scan of active hosts
            for ip in active_ips:
                if scan_stop_event.is_set():
                    break

                print(f"Detailed scan of {ip}")
                node = nodes.get_node(ip)

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
                discovered_nodes[ip] = node

            # Wait before next scan cycle
            for _ in range(50):  # 5 seconds with frequent checks for stop event
                if scan_stop_event.is_set():
                    break
                time.sleep(0.1)

        except Exception as e:
            raise
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
async def get_nodes() -> List[Node]:
    return list(nodes.get_nodes())


nodes = Nodes(localhost_ip=get_lan_ip())
scan_thread: Optional[threading.Thread] = None
scan_stop_event = threading.Event()
