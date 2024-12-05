<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import { getNodesNodesGet, startScanStartScanPost, stopScanStopScanPost } from "$lib/api";
    import type { Node } from "$lib/api";
    import cytoscape from "cytoscape";

    let container: HTMLDivElement;
    let cy: cytoscape.Core;
    let scanning = false;
    let nodes: Node[] = [];
    let updateInterval: number | undefined;

    onMount(() => {
        cy = cytoscape({
            container: document.getElementById('cy'),
            style: [
                {
                    selector: 'node',
                    style: {
                        'background-color': '#666',
                        'label': 'data(label)',
                        'text-wrap': 'wrap',
                        'text-max-width': '80px'
                    }
                },
                {
                    selector: 'node[type="gateway"]',
                    style: {
                        'background-color': '#ff6b6b',
                        'width': '60px',
                        'height': '60px'
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 2,
                        'line-color': '#ccc',
                        'curve-style': 'bezier'
                    }
                }
            ],
            layout: {
                name: 'concentric'
            }
        });

        // Add node click handler for details
        cy.on('tap', 'node', function(evt) {
            const node = evt.target;
            const data = node.data();
            alert(
                `IP: ${data.id}\n` +
                `Hostname: ${data.label}\n` +
                `Type: ${data.type}\n` +
                `OS: ${data.os || 'Unknown'}\n` +
                `MAC: ${data.mac || 'Unknown'}\n` +
                `Hop Distance: ${data.hopDistance || 'Unknown'}\n` +
                `Open Ports: ${data.ports || 'None'}`
            );
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
        const response = await startScanStartScanPost();
        if (response.error) {
            throw new Error("Error starting scan");
        }
        scanning = true;
        updateInterval = setInterval(fetchNodes, 5000);
    }

    async function stopScan() {
        const response = await stopScanStopScanPost();
        if (response.error) {
            throw new Error("Error stopping scan");
        }
        scanning = false;
        if (updateInterval) {
            clearInterval(updateInterval);
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

    function updateGraph(nodes: Node[]) {
        if (!cy) return;

        // Remove all existing elements
        cy.elements().remove();

        // Add all nodes first
        nodes.forEach((node) => {
            cy.add({
                group: 'nodes',
                data: {
                    id: node.ip,
                    label: node.hostname || node.ip,
                    type: node.gateway ? 'gateway' : 'host',
                    hopDistance: node.hop_distance,
                    os: node.os,
                    ports: node.open_ports.map(p => `${p.port}/${p.service}`).join(', '),
                    mac: node.mac_address
                }
            });
        });

        // Add edges based on connected_to information
        nodes.forEach((node) => {
            if (node.connected_to) {
                node.connected_to.forEach((targetIp) => {
                    // Only add edge if both nodes exist
                    if (cy.$id(targetIp).length > 0) {
                        cy.add({
                            group: 'edges',
                            data: {
                                id: `${node.ip}-${targetIp}`,
                                source: node.ip,
                                target: targetIp
                            }
                        });
                    }
                });
            }
        });

        // Apply layout
        const layout = cy.layout({
            name: 'concentric',
            concentric: function(node) {
                // Place gateway nodes in the center
                return node.data('type') === 'gateway' ? 2 : 
                       (node.data('hopDistance') || 1);
            },
            levelWidth: function() { return 1; },
            minNodeSpacing: 50,
            animate: true
        });
        layout.run();
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
            <div id="cy" class="w-full h-[600px] border rounded-lg"></div>
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
