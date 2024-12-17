<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import {
        getNodesNodesGet,
        startScanStartScanPost,
        stopScanStopScanPost,
        getNodesDescriptionNetworkSummaryGet,
        scanHostScanHostPost,
    } from "$lib/api";
    import type { Node } from "$lib/api";
    import cytoscape from "cytoscape";
    import { marked } from "marked";

    let container: HTMLDivElement;
    let cy: cytoscape.Core;
    let scanning = false;
    let nodes: Node[] = [];
    let updateInterval: number | undefined;
    let networkSummary: string = ""; // New state variable
    let selectedNodeId: string | null = null;
    let nodeListContainer: HTMLDivElement;
    let externalHost: string = "";

    onMount(() => {
        cy = cytoscape({
            container: container,
            style: [
                {
                    selector: "node",
                    style: {
                        "background-color": "#666",
                        label: "data(label)",
                        "text-wrap": "wrap",
                        "text-max-width": "80px",
                    },
                },
                {
                    selector: 'node[type="gateway"]',
                    style: {
                        "background-color": "#ff6b6b",
                        width: "60px",
                        height: "60px",
                    },
                },
                {
                    selector: "edge",
                    style: {
                        width: 2,
                        "line-color": "#ccc",
                        "curve-style": "bezier",
                    },
                },
            ],
            layout: {
                name: "concentric",
            },
        });

        // Replace existing node click handler
        cy.on("tap", "node", function (evt) {
            const node = evt.target;
            const data = node.data();
            selectedNodeId = data.id;

            // Find and scroll to the corresponding list item
            const listItem = document.querySelector(`[data-node-id="${data.id}"]`);
            if (listItem) {
                listItem.scrollIntoView({ behavior: "smooth", block: "center" });
            }
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
        let updateInterval = setInterval(fetchNodes, 5000); // mancava il let
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
        await fetchNetworkSummary(); // Call after nodes are updated
    }

    async function fetchNetworkSummary() {
        try {
            const response = await getNodesDescriptionNetworkSummaryGet();
            const data = response.data;
            if (!data) {
                throw new Error("No data returned");
            }
            networkSummary = data.description;
        } catch (error) {
            console.error("Error fetching network summary:", error);
            networkSummary = "Failed to load network summary.";
        }
    }

    function updateGraph(newNodes: Node[]) {
        if (!cy) return;

        // Create sets for efficient lookup
        const newNodeIds = new Set(newNodes.map((n) => n.ip));
        const existingNodeIds = new Set(cy.nodes().map((n) => n.id()));

        // Remove nodes that no longer exist
        existingNodeIds.forEach((id) => {
            if (!newNodeIds.has(id)) {
                cy.$id(id).remove();
            }
        });

        // Update or add nodes
        newNodes.forEach((node) => {
            const cyNode = cy.$id(node.ip);
            const nodeData = {
                id: node.ip,
                label: node.hostname || node.ip,
                type: node.node_type || "host", // Use node_type instead of gateway flag
                hopDistance: node.hop_distance,
                os: node.os,
                ports: node.open_ports?.map((p) => `${p.port}/${p.service}`).join(", ") || "No open ports",
                mac: node.mac_address,
            };

            if (cyNode.length > 0) {
                // Update existing node
                cyNode.data(nodeData);
            } else {
                // Add new node
                cy.add({
                    group: "nodes",
                    data: nodeData,
                });
            }
        });

        // Update edges
        cy.edges().remove(); // Remove all edges as they're lightweight
        newNodes.forEach((node) => {
            if (node.connected_to) {
                node.connected_to.forEach((targetIp) => {
                    if (cy.$id(targetIp).length > 0) {
                        const edgeId = `${node.ip}-${targetIp}`;
                        // Skip if edge already exists
                        if (!cy.$id(edgeId).length) {
                            cy.add({
                                group: "edges",
                                data: {
                                    id: edgeId,
                                    source: node.ip,
                                    target: targetIp,
                                },
                            });
                        }
                    }
                });
            }
        });

        // Run layout only if there are changes
        if (existingNodeIds.size !== newNodeIds.size) {
            const layout = cy.layout({
                name: "concentric",
                concentric: function (node) {
                    return node.data("type") === "gateway" ? 2 : 2 - node.data("hopDistance") || 1;
                },
                levelWidth: () => 1,
                minNodeSpacing: 50,
                animate: true,
            });
            layout.run();
        }
    }

    function handleListItemClick(nodeId: string) {
        selectedNodeId = nodeId;

        // Highlight the corresponding node in the graph
        cy.$("node").removeClass("selected");
        const node = cy.$id(nodeId);
        if (node) {
            node.addClass("selected");
            // Center the view on the selected node
            cy.animate({
                center: { eles: node },
                duration: 500,
            });
        }
    }

    function handleKeyDown(event: KeyboardEvent, nodeId: string) {
        if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            handleListItemClick(nodeId);
        }
    }
</script>

<div class="container mx-auto p-4">
    <div class="mb-4 flex justify-between items-center">
        <h1 class="text-2xl font-bold">Network Topology Mapper</h1>
        <div class="flex gap-4">
            <!-- Add external host scan form -->
            {#if scanning}
                <form
                    class="flex gap-2"
                    on:submit|preventDefault={async () => {
                        if (externalHost) {
                            const response = await scanHostScanHostPost({ body: { ip: externalHost } });
                            if (response.data) {
                                fetchNodes();
                            } else {
                                console.error("Error scanning external host:", response.error);
                            }
                            externalHost = ""; // Clear input after scan
                        }
                    }}
                >
                    <input
                        type="text"
                        bind:value={externalHost}
                        placeholder="IP or subnet (e.g. 8.8.8.8 or 1.1.1.0/24)"
                        class="px-3 py-2 border rounded"
                    />
                    <button
                        type="submit"
                        class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                        disabled={!externalHost}
                    >
                        Scan External
                    </button>
                </form>
            {/if}
            <!-- Existing scan buttons -->
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
            <div id="cy" bind:this={container} class="w-full h-[600px] border rounded-lg"></div>
        </div>
        <div class="h-[600px] flex flex-col overflow-hidden">
            <!-- Network Summary Section -->
            <div class="bg-gray-100 p-4 rounded-lg mb-4 shrink-0 flex flex-col" style="max-height: 200px;">
                <h2 class="text-xl font-bold mb-4 shrink-0">Network Architecture Summary</h2>
                <div class="overflow-y-auto pr-2 -mr-2">
                    {#if networkSummary}
                        <div class="prose max-w-none pb-2">
                            {@html marked(networkSummary)}
                        </div>
                    {:else}
                        <p class="text-gray-600">Loading network summary...</p>
                    {/if}
                </div>
            </div>

            <!-- Nodes List Section with Scroll -->
            <div class="bg-gray-100 p-4 rounded-lg flex-1 min-h-0 flex flex-col">
                <h2 class="text-xl font-bold mb-4 shrink-0">Discovered Nodes</h2>
                <div class="flex-1 overflow-y-auto pr-2 -mr-2" bind:this={nodeListContainer}>
                    <div class="space-y-4 pb-4">
                        {#each nodes as node}
                            <div
                                role="button"
                                tabindex="0"
                                class="bg-white p-4 rounded shadow cursor-pointer transition-colors duration-200 hover:bg-gray-50"
                                class:bg-blue-50={selectedNodeId === node.ip}
                                data-node-id={node.ip}
                                on:click={() => handleListItemClick(node.ip)}
                                on:keydown={(e) => handleKeyDown(e, node.ip)}
                            >
                                <h3 class="font-bold">{node.hostname || node.ip}</h3>
                                <p>IP: {node.ip}</p>
                                {#if node.mac_address && node.mac_address !== "unknown"}
                                    <p>MAC: {node.mac_address}</p>
                                    {#if node.vendor}
                                        <p>Vendor: {node.vendor}</p>
                                    {/if}
                                {/if}
                                {#if node.os}
                                    <p>OS: {node.os}</p>
                                {/if}
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
                                {#if node.hop_distance}
                                    <p class="text-sm text-gray-500 mt-2">Hop Distance: {node.hop_distance}</p>
                                {/if}
                                <p class="text-sm text-gray-500 mt-2">
                                    Last seen: {new Date(node.last_seen).toLocaleString()}
                                </p>
                            </div>
                        {/each}
                    </div>
                </div>
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

    /* Add styles for selected node in the graph */
    :global(.selected) {
        border-width: 3px !important;
        border-color: #3b82f6 !important;
        border-style: solid !important;
    }
</style>
