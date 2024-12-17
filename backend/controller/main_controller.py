from pathlib import Path
import socket
import threading
import time
from datetime import datetime
from functools import lru_cache
import traceback
from typing import List, Optional
import netifaces
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

import psutil
from fastapi import FastAPI
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware

from model.hop import Hop
from model.node import Node
from model.nodes import Nodes
from controller.nmap_wrapper import NmapWrapper as PortScanner
from controller.network_summary import talk_about_nodes

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_host_threads = {}  # Track external scan threads by IP

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

def get_default_gateway():
    """Get the default gateway IP address"""
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    return default_gateway

def detailed_host_scan(ip: str, nm: PortScanner, nodes: Nodes) -> None:
    """Perform detailed scan of a single host"""
    if scan_stop_event.is_set():
        return

    print(f"Detailed scan of {ip}")
    node = nodes.get_node(ip)

    try:
        # Get hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            node.update_basic_info(hostname=hostname)
        except socket.herror:
            pass

        # Version detection and OS scan
        nm.scan(ip, arguments="-sV -T4 --version-intensity 5 -O")

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
            if 'osmatch' in nm[ip] and len(nm[ip]['osmatch']) > 0:
                node.update_basic_info(os=nm[ip]['osmatch'][0].get('name'))
        node.update_ports(open_ports)

        # Update last seen timestamp
        node.touch()

    except Exception as e:
        print(f"Error scanning {ip}: {str(e)}")

def scan_network():
    try:
        # Step 1: Fast ping sweep of the entire subnet
        nm = PortScanner()
        print("Starting fast ping sweep...")
        active_ips = set()

        refresh_network_summary()
        if scan_stop_event.is_set():
            return

        # Initial scan with MAC address detection and traceroute
        nm.scan(hosts="192.168.1.0/24", arguments="-sn --traceroute")

        # Process discovered hosts
        for ip in nm.all_hosts():
            if nm[ip].state() != 'down':
                active_ips.add(ip)
                if not nodes.contains_ip(ip):
                    # Get MAC address and vendor from initial scan
                    mac = "unknown"
                    vendor = None
                    if 'addresses' in nm[ip]:
                        mac = nm[ip]['addresses'].get('mac', "unknown")
                        vendor = nm[ip].get('vendor', {}).get(mac)

                    # Create new node
                    node = Node(ip=ip, mac_address=mac, vendor=vendor, status="up", last_seen=datetime.now().isoformat())
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

        # Step 2: Identify LAN gateway
        handle_connections_to_gateway(active_ips)

        refresh_network_summary()
        if scan_stop_event.is_set():
            return

        # Step 3: Detailed scan of active hosts in parallel
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for ip in active_ips:
                if scan_stop_event.is_set():
                    break
                # Create a new scanner instance for each thread
                nm = PortScanner()
                futures.append(
                    executor.submit(detailed_host_scan, ip, nm, nodes)
                )

            # Wait for all scans to complete or until stop is requested
            concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_EXCEPTION)

            # Check for exceptions
            for future in futures:
                if future.exception():
                    print(f"Scan error: {future.exception()}")

        refresh_network_summary()


    except Exception as e:
        print(f"Error during network scan: {str(e)}")
        traceback.print_exc()


def handle_connections_to_gateway(active_ips):
    gateway_ip = get_default_gateway()
    if gateway_ip and gateway_ip in active_ips:
        gateway_node = nodes.get_node(gateway_ip)
        if gateway_node:
            gateway_node.node_type = "gateway"
            gateway_node.connected_to = []  # Reset gateway connections

            # Get all nodes connected to localhost
            localhost_node = nodes.get_node(get_lan_ip())
            if localhost_node:
                # Reset localhost connections except to gateway
                localhost_node.connected_to = [gateway_ip]

                # Process all active nodes
                for node_ip in active_ips:
                    if node_ip != gateway_ip and node_ip != get_lan_ip():
                        # Add connection from gateway to node
                        gateway_node.connected_to.append(node_ip)

                        # Reset node's connections to only point to gateway
                        node = nodes.get_node(node_ip)
                        if node:
                            node.connected_to = []  # Clear existing connections


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


class HostScanRequest(BaseModel):
    ip: str

def external_host_scan(host_ip: str):
    """Background task for external host scanning"""
    try:
        nm = PortScanner()
        print(f"Starting external scan of {host_ip}")
        nm.scan(hosts=host_ip, arguments="-sn --traceroute")
        # ...existing scan_host function body...
        found_hosts = []

        for ip in nm.all_hosts():
            if nm[ip].state() != 'down':
                if not nodes.contains_ip(ip):
                    # Create new node
                    node = Node(
                        ip=ip,
                        status="up",
                        last_seen=datetime.now().isoformat()
                    )

                    # Try to get hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        node.update_basic_info(hostname=hostname)
                    except socket.herror:
                        pass

                    nodes.add_node(node)
                    found_hosts.append(ip)

                # Process traceroute data to find closest node to our network
                if 'trace' in nm[ip]:
                    trace_data = nm[ip]['trace']
                    closest_local_hop = None

                    # Process trace data (list of hops)
                    if isinstance(trace_data, list):
                        hops: List[Hop] = []
                        for hop in trace_data:
                            hop_ip = hop.get('ipaddr')
                            if hop_ip:
                                # Check if this hop is in our local network (192.168.1.0/24)
                                if hop_ip.startswith('192.168.1.'):
                                    closest_local_hop = hop_ip
                                hops.append(Hop.from_nmap_hop(hop))

                        nodes.add_hop_list(ip, hops)

        refresh_network_summary()
        print(f"Done external scan of {host_ip}")
    except Exception as e:
        print(f"Error scanning external host: {str(e)}")
        traceback.print_exc()
    finally:
        # Clean up thread tracking
        if host_ip in scan_host_threads:
            del scan_host_threads[host_ip]

@app.post("/scan_host")
def scan_host(host: HostScanRequest):
    """Non-blocking endpoint for external host scanning"""
    if host.ip in scan_host_threads and scan_host_threads[host.ip].is_alive():
        return {"message": f"Scan already in progress for {host.ip}"}

    external_scan_thread = threading.Thread(
        target=external_host_scan,
        args=(host.ip,),
        daemon=True
    )
    scan_host_threads[host.ip] = external_scan_thread
    external_scan_thread.start()

    return {"message": f"Started scan of {host.ip}"}

@app.get("/nodes", response_model=List[Node])
async def get_nodes() -> List[Node]:
    return list(nodes.get_nodes())


class NetworkSummary(BaseModel):
    description: str


@app.get("/network-summary", response_model=NetworkSummary)
async def get_nodes_description():
    return NetworkSummary(description=network_summary)


def refresh_network_summary():
    threading.Thread(target=network_summary_thread_func, daemon=True).start()
    nodes.save_to_sqlite(str(Path(__file__).parent / "../nodes.db"))

def network_summary_thread_func():
    global network_summary
    network_summary = "(Summary refresh in progress...)\n" + network_summary
    all_nodes = nodes.get_nodes()
    network_summary = talk_about_nodes(all_nodes)



network_summary = ""
nodes = Nodes(localhost_ip=get_lan_ip(), gateway_ip=get_default_gateway())
scan_thread: Optional[threading.Thread] = None
scan_stop_event = threading.Event()
