import asyncio
import json
from pathlib import Path
import tempfile
import unittest

from gcn_zkit.project import Project
from gcn_zkit.architecture import audit as architecture
from gcn_zkit.coverage import audit as coverage


class ProjectAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / 'project.json'
        self.config = {'schema_version': 1, 'id': 'other-game', 'repositories': {'port': {
            'root': '.', 'role': 'native', 'architecture': {
                'scan': ['engine'], 'include_roots': ['engine'], 'documents': ['DESIGN.md'],
                'rules': [{'id': 'simulation-seam', 'sources': '^engine/simulation/',
                           'forbidden_includes': '(^|/)(device|presentation)/|^GraphicsAPI/',
                           'allow_includes': ['(^|/)device/Events.hpp$'], 'reason': 'Use native requests'}]},
            'coverage': {'effects': {
                'boundary': 'Declared source effects through converted and registered inventories; no execution proof.',
                'reference': {'files': ['original.json'], 'format': 'json', 'pointer': '/effects', 'id_pointer': '/name'},
                'stages': [
                    {'id': 'converted', 'inventory': {'files': ['converted/*.txt'], 'format': 'regex',
                                                      'pattern': '^asset (?P<id>[^\\n]+)$'}},
                    {'id': 'registered', 'requires': ['converted'], 'inventory': {
                        'files': ['runtime.json'], 'format': 'json'}}]}}}}}
        self.write('engine/device/Events.hpp', '// neutral interface\n')
        self.write('engine/device/Device.hpp', '// backend\n')
        self.write('engine/presentation/View.hpp', '// view\n')
        self.write('original.json', json.dumps({'effects': [{'name': 'a'}, {'name': 'b'}, {'name': 'c'}]}))
        self.write('converted/items.txt', 'asset a\nasset b\n')
        self.write('runtime.json', '["a", "c"]')
        self.save()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')

    def save(self):
        self.manifest.write_text(json.dumps(self.config), encoding='utf-8')
        self.project = Project.load(self.manifest)

    def test_relative_include_boundary_external_api_exceptions_and_comments(self):
        self.write('engine/simulation/Actor.cpp', '// #include "device/Device.hpp"\n'
                   '/*\n#include "presentation/View.hpp"\n*/\n'
                   '#include "../device/Device.hpp"\n#include "device/Events.hpp"\n'
                   '#include <GraphicsAPI/Window.h>\n#define HEADER "device/Device.hpp"\n#include HEADER\n'
                   'auto x = R"txt(\n#include "device/Device.hpp"\n)txt";\n')
        result = architecture(self.project, 'port', all_files=True)
        self.assertFalse(result['ok'])
        self.assertEqual(result['includes_checked'], 3)
        self.assertEqual([f['reference'].rsplit(':', 1)[1] for f in result['findings']], ['5', '7'])
        self.assertEqual(result['findings'][0]['resolved'], 'engine/device/Device.hpp')
        self.assertEqual(len(result['allowed_exceptions']), 1)
        self.assertEqual(result['macro_includes'], 1)

    def test_scope_and_edits_are_current(self):
        self.write('engine/simulation/Actor.cpp', '#include "device/Device.hpp"\n')
        self.write('engine/simulation/Other.cpp', '#include "presentation/View.hpp"\n')
        result = architecture(self.project, 'port', ['engine/simulation/Actor.cpp'])
        self.assertEqual(result['files_checked'], 1)
        self.assertEqual(len(result['findings']), 1)
        self.write('engine/simulation/Actor.cpp', '#include "device/Events.hpp"\n')
        self.assertTrue(architecture(self.project, 'port', ['engine/simulation/Actor.cpp'])['ok'])

    def test_missing_explicit_scope_is_an_error(self):
        result = architecture(self.project, 'port', ['engine/typo'])
        self.assertFalse(result['ok'])
        self.assertEqual(result['files_checked'], 0)
        self.assertTrue(result['errors'])

    def test_decomp_only_project_does_not_expose_port_audits(self):
        from gcn_zkit.server import create_server
        self.config['repositories']['port']['role'] = 'decomp'
        del self.config['repositories']['port']['architecture']
        del self.config['repositories']['port']['coverage']
        self.save()
        async def scenario():
            server = create_server(self.project)
            names = {tool.name for tool in await server.list_tools()}
            self.assertNotIn('zkit_architecture', names)
            self.assertNotIn('zkit_coverage', names)
        asyncio.run(asyncio.wait_for(scenario(), 15))

    def test_missing_stage_and_dependency_are_different(self):
        result = coverage(self.project, 'port', 'effects')
        self.assertFalse(result['ok'])
        self.assertEqual(result['expected'], 3)
        self.assertEqual(result['stages'][0]['missing'], ['c'])
        self.assertEqual(result['stages'][1]['missing'], ['b'])
        self.assertEqual(result['stages'][1]['without_prerequisite'], {'converted': ['c']})
        self.assertIn('port:converted/items.txt:1', result['stages'][0]['inventory']['locations']['a'])

    def test_new_identity_is_discovered_and_provenance_changes(self):
        before = coverage(self.project, 'port', 'effects')
        self.write('original.json', json.dumps({'effects': [{'name': c} for c in 'abcd']}))
        after = coverage(self.project, 'port', 'effects')
        self.assertEqual(after['expected'], 4)
        self.assertIn('d', after['stages'][0]['missing'])
        self.assertNotEqual(before['reference']['evidence'][0]['sha256'], after['reference']['evidence'][0]['sha256'])
        self.write('converted/new.txt', 'asset c\nasset d\n')
        self.write('runtime.json', '["a","b","c","d"]')
        complete = coverage(self.project, 'port', 'effects')
        self.assertTrue(complete['inventory_covered'])
        self.assertFalse(complete['system_complete'])

    def test_empty_missing_and_duplicate_inventories_never_look_complete(self):
        self.write('converted/duplicate.txt', 'asset a\n')
        result = coverage(self.project, 'port', 'effects')
        self.assertTrue(result['errors'])
        self.assertIn('a', result['stages'][0]['inventory']['duplicates'])
        (self.root / 'original.json').unlink()
        self.assertFalse(coverage(self.project, 'port', 'effects')['ok'])
        self.write('original.json', '{"effects":[]}')
        self.assertTrue(coverage(self.project, 'port', 'effects')['errors'])

    def test_unknown_and_escaping_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            coverage(self.project, 'port', 'absent')
        self.config['repositories']['port']['coverage']['effects']['reference']['files'] = ['../outside.json']
        self.save()
        with self.assertRaises(ValueError):
            coverage(self.project, 'port', 'effects')
        with self.assertRaises(ValueError):
            architecture(self.project, 'port', ['../outside.cpp'])

    def test_cli_and_mcp_report_the_same_findings(self):
        from gcn_zkit.cli import build_parser, run
        from gcn_zkit.server import create_server
        self.write('engine/simulation/Actor.cpp', '#include "device/Device.hpp"\n')
        cases = [('architecture', ['port', '--all'], 'zkit_architecture', {'repo': 'port', 'all_files': True}),
                 ('coverage', ['port', 'effects'], 'zkit_coverage', {'repo': 'port', 'name': 'effects'})]
        async def scenario():
            server = create_server(self.project)
            for command, argv, tool, args in cases:
                expected, _ = run(build_parser().parse_args(['--project', str(self.manifest), command, *argv]))
                result = await server.call_tool(tool, {**args, 'response_format': 'json'})
                blocks = result[0] if isinstance(result, tuple) else result
                self.assertEqual(json.loads(''.join(b.text for b in blocks)), expected)
        asyncio.run(asyncio.wait_for(scenario(), 15))
