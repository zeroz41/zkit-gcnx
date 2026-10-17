"""Regressions from agent workflows: exact selection, script discovery and install provenance."""
import support  # noqa: F401  (isolates config, cache and state)
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
        from zkit.native import impact
        from zkit.project import Project
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

    def test_budget_keeps_direct_and_fills_near_cheapest_first(self):
        from zkit.native import impact
        from zkit.project import Project
        build = self.native / 'build'
        build.mkdir()
        self.write_native('src/actors/Enemy.hpp', 'void check();\n')
        self.write_native('src/actors/Mid.hpp', '#include "actors/Enemy.hpp"\n')
        self.write_native('tests/Check.cpp', '#include "actors/Enemy.hpp"\n')
        self.write_native('tests/Near.cpp', '#include "actors/Mid.hpp"\n')
        (build / 'compile_commands.json').write_text(json.dumps([
            {'file': str(self.native / 'tests/Check.cpp'), 'output': 'CMakeFiles/check.dir/Check.cpp.o'},
            {'file': str(self.native / 'tests/Near.cpp'), 'output': 'CMakeFiles/near.dir/Near.cpp.o'}]), encoding='utf-8')
        test = lambda name, program: {'name': name, 'command': [str(build / program)],
                                      'properties': [{'name': 'LABELS', 'value': ['local']}]}
        (build / 'catalog.json').write_text(json.dumps({'tests': [
            test('direct-a', 'check'), test('near-costly', 'near'), test('near-mid', 'near'),
            test('near-cheap', 'near'), test('near-unmeasured', 'near')]}), encoding='utf-8')
        (build / 'Testing/Temporary').mkdir(parents=True)
        (build / 'Testing/Temporary/CTestCostData.txt').write_text(
            'direct-a 1 3\nnear-costly 1 100\nnear-mid 1 5\nnear-cheap 1 2\n', encoding='utf-8')
        config = json.loads(self.manifest.read_text(encoding='utf-8'))
        config['repositories']['native']['tests'] = {'build_dir': 'build', 'catalog': 'build/catalog.json'}
        self.manifest.write_text(json.dumps(config), encoding='utf-8')
        project = Project.load(self.manifest)
        everything = impact(project, 'native', ['src/actors/Enemy.hpp'])
        self.assertEqual(everything['groups']['near']['local'], ['near-cheap', 'near-costly', 'near-mid', 'near-unmeasured'])
        self.assertNotIn('deferred', everything['totals'])
        budgeted = impact(project, 'native', ['src/actors/Enemy.hpp'], budget=10)
        self.assertEqual(budgeted['groups']['direct']['local'], ['direct-a'])
        self.assertEqual(budgeted['groups']['near']['local'], ['near-cheap', 'near-mid'])  # 3 + 2 + 5 = 10 s
        self.assertEqual(budgeted['deferred'], ['near-costly', 'near-unmeasured'])
        self.assertEqual(budgeted['totals']['deferred'], {'tests': 2, 'budget_seconds': 10, 'serial_seconds': 100.0,
                                                          'unknown_costs': 1})
        self.assertTrue(re.fullmatch(budgeted['command_argvs']['deferred'][0][4], 'near-costly'))
        # A second program reached only by a pricier test still gets exercised before cheaper repeats.
        self.write_native('tests/Other.cpp', '#include "actors/Mid.hpp"\n')
        compile_db = json.loads((build / 'compile_commands.json').read_text(encoding='utf-8'))
        compile_db.append({'file': str(self.native / 'tests/Other.cpp'), 'output': 'CMakeFiles/other.dir/Other.cpp.o'})
        (build / 'compile_commands.json').write_text(json.dumps(compile_db), encoding='utf-8')
        catalog = json.loads((build / 'catalog.json').read_text(encoding='utf-8'))
        catalog['tests'].append(test('other-program', 'other'))
        (build / 'catalog.json').write_text(json.dumps(catalog), encoding='utf-8')
        with (build / 'Testing/Temporary/CTestCostData.txt').open('a', encoding='utf-8') as costs:
            costs.write('other-program 1 4\n')
        diverse = impact(project, 'native', ['src/actors/Enemy.hpp'], budget=10)
        self.assertEqual(sorted(diverse['groups']['near']['local']), ['near-cheap', 'other-program'])  # 3 + 2 + 4
        self.assertIn('near-mid', diverse['deferred'])
        tight = impact(project, 'native', ['src/actors/Enemy.hpp'], budget=0)
        self.assertEqual(tight['groups']['direct']['local'], ['direct-a'])  # direct tests are never dropped
        self.assertEqual(len(tight['deferred']), 5)

    def test_gate_names_the_owning_checks_of_the_diff(self):
        from zkit.project import Project
        from zkit.session import gate
        from zkit.render import gate as render_gate
        build = self.native / 'build'
        build.mkdir()
        self.write_native('tests/Check.cpp', '#include "actors/Enemy.cpp"\n')
        (build / 'compile_commands.json').write_text(json.dumps([{
            'file': str(self.native / 'tests/Check.cpp'), 'output': 'CMakeFiles/check.dir/Check.cpp.o'}]), encoding='utf-8')
        (build / 'catalog.json').write_text(json.dumps({'tests': [
            {'name': 'enemy-check', 'command': [str(build / 'check')], 'properties': [
                {'name': 'LABELS', 'value': ['local']}]}]}), encoding='utf-8')
        config = json.loads(self.manifest.read_text(encoding='utf-8'))
        config['repositories']['native']['tests'] = {'build_dir': 'build', 'catalog': 'build/catalog.json'}
        self.manifest.write_text(json.dumps(config), encoding='utf-8')
        project = Project.load(self.manifest)
        self.write_native('src/actors/Enemy.cpp', '// Original enemy update 80003000.\nvoid EnemyController::update() {}\n')
        data = gate(project, 'native')
        self.assertEqual(data['owning_tests']['tests'], 1)
        self.assertIn('enemy\\-check', data['owning_tests']['commands'][0])
        self.assertIn('owning checks for this diff', render_gate(data))

    def test_long_selection_never_expands_to_label(self):
        from zkit.native import _test_commands
        names = [f'local-{i:04}-shared-render-scene-variant-check' for i in range(400)]
        commands = _test_commands('build with spaces', names)
        self.assertGreater(len(commands), 1)
        patterns = [re.compile(cmd[cmd.index('-R') + 1]) for cmd in commands]
        self.assertTrue(all(sum(bool(p.fullmatch(name)) for p in patterns) == 1 for name in names))
        self.assertFalse(any(p.fullmatch('local-unrelated-expensive-render-matrix') for p in patterns))
        self.assertTrue(all('-L' not in cmd and '--no-tests=error' in cmd for cmd in commands))

    def test_brief_surfaces_project_architecture_and_missing_contracts(self):
        from zkit.project import Project
        from zkit.session import brief
        from zkit.render import brief as render_brief
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
        from zkit.native import IncludeGraph
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
        from zkit.server import create_server
        from mcp.server.fastmcp.exceptions import ToolError
        from zkit.activity import handoffs
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
        from zkit.health import installation
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
                'CODEX_HOME': temp, 'CLAUDE_CONFIG_DIR': temp}):
            cached = Path(temp) / 'plugins/cache/local/zkit/current'
            for folder in ('skills', 'hooks', '.codex-plugin', '.claude-plugin'):
                shutil.copytree(source / folder, cached / folder)
            result = installation()
            self.assertTrue(result['plugin_caches']['codex'][0]['current'])
            skill = cached / 'skills/zkit-resume/SKILL.md'
            skill.write_text('obsolete workflow', encoding='utf-8')
            result = installation()
            self.assertFalse(result['plugin_caches']['codex'][0]['current'])
            self.assertIn('skills/zkit-resume/SKILL.md', result['plugin_caches']['codex'][0]['different_files'])

    def test_codex_disabled_is_not_installed_and_current(self):
        from zkit.health import _codex_plugin
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'CODEX_HOME': temp}):
            config = Path(temp) / 'config.toml'
            config.write_text('[plugins."zkit@zkit"]\nenabled = false\n', encoding='utf-8')
            self.assertFalse(_codex_plugin()[0])
            config.write_text('[plugins."zkit@zkit"]\nenabled = true\n', encoding='utf-8')
            self.assertTrue(_codex_plugin()[0])

    def test_codex_local_refresh_does_not_request_git_upgrade(self):
        from zkit.onboard import connect_agents
        with tempfile.TemporaryDirectory() as source, \
             patch('zkit.health._claude_plugin', return_value=(True, 'enabled')), \
             patch('zkit.health._codex_plugin', return_value=(True, 'enabled')), \
             patch('shutil.which', side_effect=lambda name: name):
            text = '\n'.join(connect_agents(True, refresh=True, source=source))
            self.assertIn('codex plugin add zkit@zkit', text)
            self.assertNotIn('codex plugin marketplace upgrade', text)
            self.assertIn('claude plugin marketplace update zkit', text)

    def test_refresh_agents_dry_run_does_not_skip_existing_plugins(self):
        from zkit.onboard import connect_agents
        with patch('zkit.health._claude_plugin', return_value=(True, 'enabled')), \
             patch('zkit.health._codex_plugin', return_value=(True, 'enabled')), \
             patch('shutil.which', side_effect=lambda name: name), \
             patch('subprocess.run') as run:
            text = '\n'.join(connect_agents(True, refresh=True, source='/work/toolkit'))
            self.assertIn('claude plugin update zkit@zkit', text)
            self.assertIn('codex plugin marketplace upgrade zkit', text)
            self.assertIn('/work/toolkit', text)
            run.assert_not_called()

class TestPlanTests(unittest.TestCase):
    setUp = test_bridge.BridgeTests.setUp
    write_native = test_bridge.BridgeTests.write_native

    def plan_project(self):
        from zkit.project import Project
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
        from zkit.native import test_plan
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
        from zkit.native import test_plan
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
        from zkit.native import _fixture_build
        build = self.native / 'build'
        command = ['cmake', '--build', str(build), '--target', 'alpha']
        props = [{'name': 'FIXTURES_SETUP', 'value': ['a']}]
        for extra in ({'name': 'ENVIRONMENT', 'value': ['MODE=one']},
                      {'name': 'DEPENDS', 'value': ['prepare']},
                      {'name': 'FIXTURES_REQUIRED', 'value': ['prepare']}):
            self.assertIsNone(_fixture_build({'command': command, 'properties': props + [extra]}, build))
        self.assertIsNone(_fixture_build({'command': command + ['--', '-custom'], 'properties': props}, build))

    def test_cli_and_mcp_share_the_plan(self):
        from zkit.cli import build_parser, run
        from zkit.server import create_server
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
