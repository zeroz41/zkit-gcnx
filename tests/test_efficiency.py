"""Regressions from agent workflows: exact selection, script discovery and install provenance."""
import asyncio
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

import test_bridge


class ImpactTests(unittest.TestCase):
    setUp = test_bridge.BridgeTests.setUp
    write_native = test_bridge.BridgeTests.write_native

    def test_script_registration_fixtures_and_gpu_are_explicit(self):
        from gcn_zkit.native import impact
        from gcn_zkit.project import Project
        self.write_native("tests/check.py", "print('registered script')\n")
        build = self.native / 'build'
        build.mkdir()
        self.write_native('tests/Check.cpp', '#include "actors/Enemy.hpp"\n')
        self.write_native('src/actors/Enemy.hpp', 'void check();\n')
        (build / 'compile_commands.json').write_text(json.dumps([{
            'file': str(self.native / 'tests/Check.cpp'), 'output': 'CMakeFiles/check.dir/Check.cpp.o'}]), encoding='utf-8')
        (build / 'catalog.json').write_text(json.dumps({'tests': [
            {'name': 'script-check', 'command': ['python', '../tests/check.py'], 'properties': []},
            {'name': 'field-gpu', 'command': [str(build / 'check')], 'properties': [
                {'name': 'LABELS', 'value': ['local', 'gpu']},
                {'name': 'FIXTURES_REQUIRED', 'value': ['build-check']}]},
            {'name': 'disabled-check', 'command': [str(build / 'check')], 'properties': [
                {'name': 'DISABLED', 'value': True}]}]}), encoding='utf-8')
        config = json.loads(self.manifest.read_text(encoding='utf-8'))
        config['repositories']['native']['tests'] = {'build_dir': 'build', 'catalog': 'build/catalog.json'}
        self.manifest.write_text(json.dumps(config), encoding='utf-8')
        result = impact(Project.load(self.manifest), 'native', ['src/actors/Enemy.hpp', 'tests/check.py'])
        self.assertEqual(result['groups']['direct'], {'gpu': ['field-gpu'], 'unlabelled': ['script-check']})
        self.assertEqual(result['build_targets']['direct/gpu'], ['check'])
        self.assertEqual(result['fixtures']['direct/gpu'], ['build-check'])
        self.assertEqual(result['totals']['direct/gpu']['unknown_costs'], 1)
        self.assertEqual(result['untested_files'], [])

    def test_long_selection_never_expands_to_label(self):
        from gcn_zkit.native import _test_commands
        names = [f'local-{i:04}-shared-render-scene-variant-check' for i in range(400)]
        commands = _test_commands('build with spaces', names)
        self.assertGreater(len(commands), 1)
        patterns = [re.compile(cmd[cmd.index('-R') + 1]) for cmd in commands]
        self.assertTrue(all(sum(bool(p.fullmatch(name)) for p in patterns) == 1 for name in names))
        self.assertFalse(any(p.fullmatch('local-unrelated-expensive-render-matrix') for p in patterns))
        self.assertTrue(all('-L' not in cmd and '--no-tests=error' in cmd for cmd in commands))

    def test_brief_surfaces_project_architecture_and_missing_contracts(self):
        from gcn_zkit.project import Project
        from gcn_zkit.session import brief
        from gcn_zkit.render import brief as render_brief
        self.write_native('design/Architecture.md', '# Architecture\nOne mutable owner per system.\n')
        config = json.loads(self.manifest.read_text(encoding='utf-8'))
        config['repositories']['native']['required_docs'] = ['design/Architecture.md', 'design/Quality.md']
        self.manifest.write_text(json.dumps(config), encoding='utf-8')
        data = brief(Project.load(self.manifest), 'native')
        self.assertEqual(data['repos']['native']['required_reading'], [
            {'reference': 'native:design/Architecture.md', 'exists': True},
            {'reference': 'native:design/Quality.md', 'exists': False}])
        for compact in (False, True):
            text = render_brief(data, compact=compact)
            self.assertIn('native:design/Architecture.md', text)
            self.assertIn('native:design/Quality.md [MISSING]', text)

    def test_include_resolution_preserves_relative_precedence_and_edits(self):
        from gcn_zkit.native import IncludeGraph
        self.write_native('src/actors/same.hpp', 'local\n')
        self.write_native('src/same.hpp', 'root\n')
        self.write_native('src/actors/Use.cpp', '#include "same.hpp"\n')
        graph = IncludeGraph(self.native, ['src'], ['src'])
        self.assertIn('src/actors/Use.cpp', graph.includers['src/actors/same.hpp'])
        self.assertNotIn('src/actors/Use.cpp', graph.includers['src/same.hpp'])
        self.write_native('src/actors/Use.cpp', '#include "../same.hpp"\n')
        graph = IncludeGraph(self.native, ['src'], ['src'])
        self.assertIn('src/actors/Use.cpp', graph.includers['src/same.hpp'])

    def test_observed_mcp_aliases_keep_validation_and_handoff_content(self):
        from gcn_zkit.server import create_server
        from mcp.server.fastmcp.exceptions import ToolError
        from gcn_zkit.activity import handoffs
        server = create_server(self.project)
        async def scenario():
            def text(result):
                return ''.join(b.text for b in (result[0] if isinstance(result, tuple) else result))
            self.assertIn('0x80003000', text(await server.call_tool('zkit_lookup', {'address': '80003000'})))
            self.assertIn('0x80003000', text(await server.call_tool('zkit_port_plan', {'entry': '80003000'})))
            self.assertIn('0x80003010', text(await server.call_tool('zkit_asm', {
                'addrs': '["80003000", "80003010"]'})))
            self.assertIn('enemy update', text(await server.call_tool('zkit_read', {
                'path': 'native:src/actors/Enemy.cpp', 'limit': 2})))
            await server.call_tool('zkit_handoff', {'repo': 'native', 'note': 'verified checkpoint; milestone remains open'})
            self.assertEqual(handoffs(self.project)[0]['text'], 'verified checkpoint; milestone remains open')
            with self.assertRaisesRegex(ToolError, 'conflicting'):
                await server.call_tool('zkit_handoff', {'repo': 'native', 'text': 'one', 'note': 'two'})
            with self.assertRaisesRegex(ToolError, 'bogus'):
                await server.call_tool('zkit_lookup', {'address': '80003000', 'bogus': True})
        asyncio.run(asyncio.wait_for(scenario(), 15))


class InstallationTests(unittest.TestCase):
    def test_doctor_detects_stale_cached_skill_even_at_same_version(self):
        from gcn_zkit.health import installation
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
                'CODEX_HOME': temp, 'CLAUDE_CONFIG_DIR': temp}):
            cached = Path(temp) / 'plugins/cache/local/gcn-zkit/current'
            for folder in ('skills', 'hooks', '.codex-plugin', '.claude-plugin'):
                shutil.copytree(source / folder, cached / folder)
            result = installation()
            self.assertTrue(result['plugin_caches']['codex'][0]['current'])
            skill = cached / 'skills/zkit-resume/SKILL.md'
            skill.write_text('obsolete workflow', encoding='utf-8')
            result = installation()
            self.assertFalse(result['plugin_caches']['codex'][0]['current'])
            self.assertIn('skills/zkit-resume/SKILL.md', result['plugin_caches']['codex'][0]['different_files'])

    def test_replay_rejects_writes_after_global_options(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('replay', Path(__file__).resolve().parents[1] / 'tools/replay.py')
        replay = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(replay)
        for argv in (['--json', 'handoff', 'native', 'note'], ['drift', '--accept'],
                     ['--project', '/work/project.json', 'setup'], ['install', 'codex', '--write', '/repo']):
            self.assertFalse(replay.replayable({'kind': 'cli', 'argv': argv}))
        self.assertTrue(replay.replayable({'kind': 'cli', 'argv': ['--json', 'lookup', '80003000']}))
        self.assertFalse(replay.replayable({'kind': 'mcp', 'tool': 'zkit_drift', 'args': {'accept': True}}))
        self.assertEqual(replay.summarize([])['calls'], 0)

    def test_replay_extraction_scopes_direct_calls_and_excludes_review_quotes(self):
        import argparse
        import importlib.util
        spec = importlib.util.spec_from_file_location('replay', Path(__file__).resolve().parents[1] / 'tools/replay.py')
        replay = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(replay)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            session = [
                {'type': 'session_meta', 'payload': {'cwd': str(root / 'game'), 'thread_source': 'user'}},
                {'timestamp': '2026-01-02', 'payload': {'type': 'function_call',
                    'name': 'mcp__gcn_zkit__zkit_lookup', 'arguments': '{"query":"80003000"}'}},
                {'timestamp': '2026-01-04', 'payload': {'type': 'function_call',
                    'name': 'mcp__gcn_zkit__zkit_lookup', 'arguments': '{"query":"80003010"}'}}]
            (root / 'user.jsonl').write_text('\n'.join(json.dumps(r) for r in session), encoding='utf-8')
            session[0]['payload']['thread_source'] = 'guardian_review'
            (root / 'review.jsonl').write_text('\n'.join(json.dumps(r) for r in session), encoding='utf-8')
            output = root / 'calls.json'
            replay.extract(argparse.Namespace(repo_root=[str(root / 'game')], since='2026-01-01',
                until='2026-01-03', claude=str(root / 'absent'), codex=str(root), out=str(output), merge=False))
            calls = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]['seen'], 1)
            self.assertEqual(calls[0]['args']['query'], '80003000')

    def test_codex_disabled_is_not_installed_and_current(self):
        from gcn_zkit.health import _codex_plugin
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'CODEX_HOME': temp}):
            config = Path(temp) / 'config.toml'
            config.write_text('[plugins."gcn-zkit@gcn-zkit"]\nenabled = false\n', encoding='utf-8')
            self.assertFalse(_codex_plugin()[0])
            config.write_text('[plugins."gcn-zkit@gcn-zkit"]\nenabled = true\n', encoding='utf-8')
            self.assertTrue(_codex_plugin()[0])

    def test_refresh_agents_dry_run_does_not_skip_existing_plugins(self):
        from gcn_zkit.onboard import connect_agents
        with patch('gcn_zkit.health._claude_plugin', return_value=(True, 'enabled')), \
             patch('gcn_zkit.health._codex_plugin', return_value=(True, 'enabled')), \
             patch('shutil.which', side_effect=lambda name: name), \
             patch('subprocess.run') as run:
            text = '\n'.join(connect_agents(True, refresh=True, source='/work/toolkit'))
            self.assertIn('claude plugin update gcn-zkit@gcn-zkit', text)
            self.assertIn('codex plugin marketplace upgrade gcn-zkit', text)
            self.assertIn('/work/toolkit', text)
            run.assert_not_called()

class TestPlanTests(unittest.TestCase):
    setUp = test_bridge.BridgeTests.setUp
    write_native = test_bridge.BridgeTests.write_native

    def plan_project(self):
        from gcn_zkit.project import Project
        build = self.native / 'build'
        build.mkdir()
        def test(name, properties, command=None):
            return {'name': name, 'command': command or ['check'],
                    'properties': [{'name': k, 'value': v} for k, v in properties.items()]}
        rows = [test('a', {'FIXTURES_REQUIRED': ['first']}), test('b', {'FIXTURES_REQUIRED': ['second']}),
                test('build-a', {'FIXTURES_SETUP': ['first']},
                     ['cmake', '--build', str(build), '--target', 'alpha', '--config', 'Release']),
                test('build-b', {'FIXTURES_SETUP': ['second']},
                     ['cmake', '--build', str(build), '--target', 'beta', 'alpha', '--config', 'Release']),
                test('cleanup-a', {'FIXTURES_CLEANUP': ['first'], 'FIXTURES_REQUIRED': ['third']}),
                test('prepare-third', {'FIXTURES_SETUP': ['third'], 'FIXTURES_REQUIRED': ['first']}),
                test('unrelated', {}), test('disabled', {'DISABLED': True})]
        (build / 'catalog.json').write_text(json.dumps({'tests': rows}), encoding='utf-8')
        (build / 'Testing/Temporary').mkdir(parents=True)
        (build / 'Testing/Temporary/CTestCostData.txt').write_text('a 1 1.5\nbuild-a 1 10\n', encoding='utf-8')
        config = json.loads(self.manifest.read_text(encoding='utf-8'))
        config['repositories']['native']['tests'] = {'build_dir': 'build', 'catalog': 'build/catalog.json'}
        self.manifest.write_text(json.dumps(config), encoding='utf-8')
        return Project.load(self.manifest)

    def test_fixture_closure_exact_selection_and_parallel_build_union(self):
        from gcn_zkit.native import test_plan
        project = self.plan_project()
        result = test_plan(project, 'native', ['b', 'a', 'a'], 4)
        self.assertTrue(result['ok'])
        self.assertFalse(result['executed'])
        self.assertEqual(result['selected'], ['a', 'b'])
        self.assertEqual(result['fixture_tests'], ['build-a', 'build-b', 'cleanup-a', 'prepare-third'])
        self.assertEqual(result['costs']['selected'], {'tests': 2, 'recorded_seconds': 1.5, 'unknown_costs': 1})
        self.assertEqual(result['costs']['fixtures']['recorded_seconds'], 10)
        self.assertEqual(len(result['prebuilds']), 1)
        prebuild = result['prebuilds'][0]
        self.assertEqual(prebuild['targets'], ['alpha', 'beta'])
        self.assertIn('--parallel', prebuild['argv'])
        command = result['ctest_argvs'][0]
        self.assertEqual(command[command.index('-R') + 1], '^(a|b)$')
        self.assertFalse(any(a.startswith('-F') for a in command))
        self.assertNotIn('unrelated', str(result))

    def test_missing_and_disabled_selection_blocks_executable_plan(self):
        from gcn_zkit.native import test_plan
        project = self.plan_project()
        result = test_plan(project, 'native', ['a', 'absent', 'disabled'])
        self.assertFalse(result['ok'])
        self.assertEqual(result['missing'], ['absent'])
        self.assertEqual(result['disabled'], ['disabled'])
        self.assertEqual(result['ctest_argvs'], [])
        self.assertEqual(result['prebuilds'], [])
        with self.assertRaises(ValueError):
            test_plan(project, 'native', [])
        with self.assertRaises(ValueError):
            test_plan(project, 'native', ['a'], 0)

    def test_complex_build_fixtures_are_not_reordered(self):
        from gcn_zkit.native import _fixture_build
        build = self.native / 'build'
        command = ['cmake', '--build', str(build), '--target', 'alpha']
        props = [{'name': 'FIXTURES_SETUP', 'value': ['a']}]
        for extra in ({'name': 'ENVIRONMENT', 'value': ['MODE=one']},
                      {'name': 'DEPENDS', 'value': ['prepare']},
                      {'name': 'FIXTURES_REQUIRED', 'value': ['prepare']}):
            self.assertIsNone(_fixture_build({'command': command, 'properties': props + [extra]}, build))
        self.assertIsNone(_fixture_build({'command': command + ['--', '-custom'], 'properties': props}, build))

    def test_cli_and_mcp_share_the_plan(self):
        from gcn_zkit.cli import build_parser, run
        from gcn_zkit.server import create_server
        project = self.plan_project()
        expected, text = run(build_parser().parse_args([
            '--project', str(self.manifest), 'test-plan', 'native', 'a', 'b', '--jobs', '4']))
        self.assertIn('nothing executed', text)
        async def scenario():
            result = await create_server(project).call_tool('zkit_test_plan', {
                'repo': 'native', 'names': ['a', 'b'], 'jobs': 4, 'response_format': 'json'})
            blocks = result[0] if isinstance(result, tuple) else result
            self.assertEqual(json.loads(''.join(b.text for b in blocks)), expected)
        asyncio.run(asyncio.wait_for(scenario(), 15))
