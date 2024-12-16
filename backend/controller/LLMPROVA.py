from typing import List
from openai import OpenAI
from model.node import Node

API_KEY = "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"
BASE_URL = "https://openrouter.ai/api/v1"

client = OpenAI(
    base_url=BASE_URL,
    api_key=API_KEY,
)


def talk_about_nodes(nodes: List[Node]) -> str:
    """
    Questa funzione prende in input una lista di nodi `Node` e restituisce
    una stringa generata dall'LLM che li descrive.
    """
    if not nodes:
        prompt = "No nodes are available."
    else:
        found_message = "The required nodes have been found. Below are their details:\n\n"

        # Includiamo tutti i campi del Node
        nodes_description = "\n\n".join([
            (
                f"IP: {node.ip}\n"
                f"MAC: {node.mac_address or 'N/A'}\n"
                f"Hostname: {node.hostname or 'unknown'}\n"
                f"OS: {node.os or 'unknown'}\n"
                f"Open Ports: {', '.join(f'{p['port']}/{p['service']}' for p in node.open_ports) if node.open_ports else 'None'}\n"
                f"Last Seen: {node.last_seen}\n"
                f"Status: {node.status}\n"
                f"Other Info: {node.other_info if node.other_info else 'None'}\n"
                f"Connected To: {', '.join(node.connected_to) if node.connected_to else 'None'}\n"
                f"Hop Distance: {node.hop_distance if node.hop_distance is not None else 'Unknown'}"
            )
            for node in nodes
        ])

        prompt = (
                "Given the following Wi-Fi router nodes information, please describe them and provide a useful analysis:\n\n"
                + found_message
                + nodes_description
                + "\n"
        )

    completion = client.chat.completions.create(
        model="meta-llama/llama-3.3-70b-instruct",
        messages=[{"role": "user", "content": prompt}]
    )
    return completion.choices[0].message.content
