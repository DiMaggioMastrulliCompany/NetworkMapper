from datetime import datetime
from typing import Dict, List

from controller.localhostinfo import get_internet_interface_info
from model.hop import Hop
from model.node import Node


class Nodes:
    localhost_ip: str
    nodes: Dict[str, Node] = {}

    def __init__(self, localhost_ip: str):
        self.localhost_ip = localhost_ip

        # Add localhost node
        self.add_node(self.get_localhost_node())

    def get_localhost_node(self) -> Node:
        localhost_info = get_internet_interface_info()
        localhost_mac = localhost_info['mac'] if localhost_info else None
        return Node(ip=self.localhost_ip, status="up", last_seen=datetime.now().isoformat(), mac_address=localhost_mac)

    def add_node(self, node: Node):
        self.nodes[node.ip] = node

    def get_nodes(self):
        return list(self.nodes.values())

    def contains_ip(self, ip: str) -> bool:
        return ip in self.nodes

    def add_hop_list(self, ip: str, hops: List[Hop]):
        if len(hops) < 1:
            return

        # if hops[-1].ip != ip:
        #     hops.append(Hop(ip=ip, ttl=0, rtt=0, host=None))

        self.nodes[self.localhost_ip].add_edge(ip)
        self.nodes[hops[0].ip].set_hop_distance(hops[0].ttl)

        for i in range(len(hops) - 1):
            current_hop = hops[i]
            next_hop = hops[i + 1]
            self.nodes[current_hop.ip].add_edge(next_hop.ip)
            self.nodes[next_hop.ip].set_hop_distance(next_hop.ttl)

    def get_node(self, ip: str) -> Node:
        return self.nodes[ip]
