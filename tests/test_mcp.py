"""Exercise actual SDK stdio negotiation and dispatch, not just Python calls."""

import support  # noqa: F401  (isolates config, cache and state)
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


@unittest.skipUnless(importlib.util.find_spec("mcp"), "Install the mcp extra for the transport test")
class McpTests(unittest.TestCase):
    def test_stdio_session(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / "AGENTS.md").write_text("Use actual evidence.", encoding="utf-8")
                manifest = root / "project.json"
                manifest.write_text(json.dumps({"schema_version": 1, "id": "transport-test", "repositories": {
                    "game": {"root": ".", "required_docs": ["AGENTS.md"], "search_paths": ["AGENTS.md"]}}}))
                env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
                           XDG_CACHE_HOME=str(root / "cache"), XDG_STATE_HOME=str(root / "state"))
                params = StdioServerParameters(command=sys.executable, args=["-m", "zkit.cli", "--project", str(manifest), "serve"], env=env)
                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                        # No native port and no recipes: the port tools are left out.
                        self.assertEqual(len(tools), 20)  # zkit_unit needs a splits file, zkit_progress a report
                        self.assertNotIn("zkit_impact", tools)
                        self.assertTrue(all(name.startswith("zkit_") for name in tools))
                        writers = {name for name, tool in tools.items() if not tool.annotations.readOnlyHint}
                        self.assertEqual(writers, {"zkit_handoff"})
                        response = await session.call_tool("zkit_brief", {})
                        self.assertFalse(response.isError)
                        self.assertIn("transport-test", response.content[0].text)
                        response = await session.call_tool("zkit_search", {"words": "actual"})
                        self.assertFalse(response.isError)
                        self.assertIn("game:AGENTS.md:1", response.content[0].text)
                        response = await session.call_tool("zkit_read", {"reference": "game:../outside.md"})
                        self.assertTrue(response.isError)
                        response = await session.call_tool("zkit_handoff", {"repo": "game", "text": "next: X"})
                        self.assertFalse(response.isError)
                        response = await session.call_tool("zkit_activity", {"response_format": "json"})
                        self.assertEqual(json.loads(response.content[0].text)["handoffs"][0]["text"], "next: X")
                        resource = await session.read_resource("zkit://project")
                        self.assertEqual(json.loads(resource.contents[0].text)["id"], "transport-test")
                        updated = json.loads(manifest.read_text(encoding="utf-8"))
                        updated["repositories"]["game"]["rules"] = ["preserve shared RNG"]
                        manifest.write_text(json.dumps(updated), encoding="utf-8")
                        response = await session.call_tool("zkit_brief", {"repo": "game"})
                        self.assertIn("preserve shared RNG", response.content[0].text)
        asyncio.run(asyncio.wait_for(scenario(), timeout=30))

    def test_native_port_tools(self):
        """A project with a native repo gets the port tools; recipe tools still need configured recipes."""
        from zkit.project import Project
        from zkit.server import create_server
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "project.json"
            manifest.write_text(json.dumps({"schema_version": 1, "id": "ported", "repositories": {
                "decomp": {"root": ".", "role": "decomp"}, "native": {"root": ".", "role": "native"}}}))
            names = {t.name for t in create_server(Project.load(manifest))._tool_manager.list_tools()}
            from zkit.index import close_connections
            close_connections()
        self.assertEqual(len(names), 29)
        self.assertTrue({"zkit_impact", "zkit_drift", "zkit_port_plan", "zkit_demand"} <= names)
        self.assertNotIn("zkit_recipes", names)
