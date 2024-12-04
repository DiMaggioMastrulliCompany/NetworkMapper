<script lang="ts">
	import "../app.css";
	import { client } from "$lib/api";
	let { children } = $props();

	client.setConfig({
		baseUrl: "http://localhost:8000",
	});
</script>

{@render children()}
