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
    Questa funzione prende in input una lista di nodi e restituisce
    una stringa generata dall'LLM che li descrive.
    """
    if not nodes:
        prompt = "No nodes are available."
    else:
        # Se abbiamo dei nodi, prima affermiamo di averli trovati:
        found_message = "The required nodes have been found. Below are their details:\n\n"

        nodes_description = "\n".join([
            f"- IP: {node.ip}, Hostname: {node.hostname or 'unknown'}, Status: {node.status}"
            for node in nodes
        ])

        prompt = (
                "Given the following Wi-Fi router nodes information, describe them:\n\n"
                + found_message
                + nodes_description
                + "\n"
        )

    completion = client.chat.completions.create(
        model="meta-llama/llama-3.3-70b-instruct",
        messages=[{"role": "user", "content": prompt}]
    )
    return completion.choices[0].message.content

#esempio di chiamta
test_nodes = [
    Node(ip="192.168.0.110", hostname="gateway_router", status="active"),
    Node(ip="192.168.0.2", hostname="office_pc", status="inactive")
]

response = talk_about_nodes(test_nodes)
print(response)

