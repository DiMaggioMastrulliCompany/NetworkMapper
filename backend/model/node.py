from datetime import datetime
from typing import Optional, List, Dict

from pydantic import BaseModel


class Node(BaseModel):
    ip: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os: Optional[str] = None
    open_ports: List[Dict[str, int | str]] = []
    last_seen: str
    status: str
    other_info: Dict[str, str] = {}
    # Topology related fields
    connected_to: List[str] = []  # List of IPs this node is connected to
    hop_distance: Optional[int] = None  # Number of hops from the scanning machine
    node_type: Optional[str] = None  # Type of node (e.g. gateway)

    def add_edge(self, ip: str):
        self.connected_to.append(ip)

    def set_hop_distance(self, distance: int) -> bool:
        if self.hop_distance is None or self.hop_distance > distance:
            self.hop_distance = distance
            return True
        return False

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
