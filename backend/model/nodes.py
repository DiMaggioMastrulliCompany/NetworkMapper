import sqlite3
import json
from datetime import datetime
import traceback
from typing import Dict, List

from controller.localhostinfo import get_internet_interface_info
from model.hop import Hop
from model.node import Node


class Nodes:
    localhost_ip: str
    gateway_ip: str
    nodes: Dict[str, Node] = {}

    def __init__(self, localhost_ip: str, gateway_ip: str):
        self.localhost_ip = localhost_ip

        self.gateway_ip = gateway_ip

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

        # Create nodes for each hop if they don't exist
        for hop in hops:
            if not self.contains_ip(hop.ip):
                # Create a new node with basic info from the hop
                new_node = Node(
                    ip=hop.ip,
                    hostname=hop.host if hop.host else None,
                    status="up",
                    last_seen=datetime.now().isoformat()
                )
                self.add_node(new_node)

        # Ensure target node exists
        if not self.contains_ip(ip):
            target_node = Node(
                ip=ip,
                status="up",
                last_seen=datetime.now().isoformat()
            )
            self.add_node(target_node)

        # Process hop connections
        if hops[0].ip.startswith("192.168."):
            # self.nodes[self.gateway_ip].add_edge(ip)
            pass
        else:
            self.nodes[self.localhost_ip].add_edge(ip)
        self.nodes[hops[0].ip].set_hop_distance(hops[0].ttl)

        for i in range(len(hops) - 1):
            current_hop = hops[i]
            next_hop = hops[i + 1]
            self.nodes[current_hop.ip].add_edge(next_hop.ip)
            self.nodes[next_hop.ip].set_hop_distance(next_hop.ttl)

    def get_node(self, ip: str) -> Node:
        return self.nodes[ip]

    def save_to_sqlite(self, db_path: str) -> None:
        """Save nodes to SQLite database"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Create or replace nodes table
            cursor.execute("DROP TABLE IF EXISTS nodes")
            cursor.execute("""
                CREATE TABLE nodes (
                    ip TEXT PRIMARY KEY,
                    mac_address TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    os TEXT,
                    last_seen TEXT,
                    status TEXT,
                    hop_distance INTEGER,
                    node_type TEXT
                )
            """)

            # Insert basic node data
            cursor.executemany("""
                INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [(
                node.ip,
                node.mac_address,
                node.hostname,
                node.vendor,
                node.os,
                node.last_seen,
                node.status,
                node.hop_distance,
                node.node_type
            ) for node in self.nodes.values()])

            conn.commit()
            print(f"Saved {len(self.nodes)} nodes to {db_path}")
        except Exception as e:
            print(f"Error saving to SQLite: {str(e)}")
            traceback.print_exc()
        finally:
            conn.close()
