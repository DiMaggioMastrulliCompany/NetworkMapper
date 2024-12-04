<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import { getNodesNodesGet } from "$lib/api";
    import type { Node } from "$lib/api";
    import cytoscape from "cytoscape";

    let container: HTMLDivElement;
    let cy: cytoscape.Core;
    let scanning = false;
    let nodes: Node[] = [];
    let updateInterval: number | undefined;

    onMount(() => {
        cy = cytoscape({
            container,
            style: [
                {
                    selector: "node",
                    style: {
                        "background-color": "#666",
                        label: "data(label)",
                        width: 60,
                        height: 60,
                    },
                },
                {
                    selector: "edge",
                    style: {
                        width: 3,
                        "line-color": "#ccc",
                        "curve-style": "bezier",
                    },
                },
            ],
        });

        fetchNodes();
    });

    onDestroy(() => {
        if (updateInterval) {
            clearInterval(updateInterval);
        }
        if (scanning) {
            stopScan();
        }
    });

    async function startScan() {
        try {
            const response = await fetch("http://localhost:8000/start_scan");
            const data = await response.json();
            scanning = true;
            updateInterval = setInterval(fetchNodes, 5000);
        } catch (error) {
            console.error("Error starting scan:", error);
        }
    }

    async function stopScan() {
        try {
            const response = await fetch("http://localhost:8000/stop_scan");
            const data = await response.json();
            scanning = false;
            if (updateInterval) {
                clearInterval(updateInterval);
            }
        } catch (error) {
            console.error("Error stopping scan:", error);
        }
    }

    async function fetchNodes() {
        const response = await getNodesNodesGet();

        if (!response.data) {
            return;
        }
        const newNodes = response.data;
        updateGraph(newNodes);
        nodes = newNodes;
    }

    function updateGraph(newNodes: Node[]) {
        cy.elements().remove();

        // Add nodes
        newNodes.forEach((node) => {
            cy.add({
                group: "nodes",
                data: {
                    id: node.ip,
                    label: `${node.hostname || node.ip}\n${node.os || "Unknown OS"}`,
                },
            });
        });

        // Layout the graph
        cy.layout({
            name: "circle",
        }).run();
    }
</script>

<div class="container mx-auto p-4">
    <div class="mb-4 flex justify-between items-center">
        <h1 class="text-2xl font-bold">Network Topology Mapper</h1>
        <div>
            {#if !scanning}
                <button
                    class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
                    on:click={startScan}
                >
                    Start Scanning
                </button>
            {:else}
                <button class="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded" on:click={stopScan}>
                    Stop Scanning
                </button>
            {/if}
        </div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="md:col-span-2">
            <div bind:this={container} class="w-full h-[600px] border rounded-lg"></div>
        </div>
        <div class="bg-gray-100 p-4 rounded-lg">
            <h2 class="text-xl font-bold mb-4">Discovered Nodes</h2>
            <div class="space-y-4">
                {#each nodes as node}
                    <div class="bg-white p-4 rounded shadow">
                        <h3 class="font-bold">{node.hostname || node.ip}</h3>
                        <p>IP: {node.ip}</p>
                        <p>OS: {node.os || "Unknown"}</p>
                        <p>Status: {node.status}</p>
                        {#if node.open_ports && node.open_ports.length > 0}
                            <div class="mt-2">
                                <p class="font-semibold">Open Ports:</p>
                                <ul class="list-disc list-inside">
                                    {#each node.open_ports as port}
                                        <li>{port.port} ({port.service} {port.version})</li>
                                    {/each}
                                </ul>
                            </div>
                        {/if}
                        <p class="text-sm text-gray-500 mt-2">Last seen: {new Date(node.last_seen).toLocaleString()}</p>
                    </div>
                {/each}
            </div>
        </div>
    </div>
</div>

<style>
    :global(html, body) {
        margin: 0;
        padding: 0;
        height: 100%;
    }
</style>
