from typing import List
import time
from openai import OpenAI, OpenAIError
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
            "\n".join(filter(None, [
                f"IP: {node.ip}",
                f"MAC: {node.mac_address}" if node.mac_address and node.mac_address != "unknown" else None,
                f"Hostname: {node.hostname}" if node.hostname and node.hostname != "unknown" else None,
                f"OS: {node.os}" if node.os and node.os != "unknown" else None,
                f"Open Ports: {', '.join(f'{p['port']}/{p['service']}' for p in node.open_ports)}" if node.open_ports else None,
                f"Status: {node.status}" if node.status else None,
                f"Other Info: {node.other_info}" if node.other_info and node.other_info != {} else None,
                f"Connected To: {', '.join(node.connected_to)}" if node.connected_to else None,
                f"Hop Distance: {node.hop_distance}" if node.hop_distance is not None else None
            ]))
            for node in nodes
        ])

        prompt = (
                "Given the following network nodes information, please describe them and provide a useful analysis. Be short and incisive, don't be unsure by writing 'it appears' or 'it might be'.\n\n"
                + found_message
                + nodes_description
                + "\n"
        )

    max_retries = 10
    retry_count = 0

    while retry_count < max_retries:
        try:
            completion = client.chat.completions.create(
                model="meta-llama/llama-3.3-70b-instruct",
                messages=[{"role": "user", "content": prompt}]
            )
            return completion.choices[0].message.content
        except OpenAIError:
            retry_count += 1
            if retry_count == max_retries:
                break
            time.sleep(1)  # Wait 1 second before retrying
    return "Summary not available. Try again later."
