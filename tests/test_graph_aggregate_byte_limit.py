import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from aural import provenance


ROOT = Path(__file__).resolve().parents[1]
CASES = (
    ROOT / 'tests' / 'fixtures' / 'graph_conformance'
    / 'aggregate-byte-limit-cases.json'
)
NODE_ADAPTER = ROOT / 'tests' / 'graph_aggregate_boundary_node_adapter.mjs'
REQUIRED_CASE_IDS = {
    'H-aggregate-bytes-at-limit',
    'N-aggregate-bytes-over-limit',
}
OPT_IN_VARIABLE = 'AURAL_RUN_LARGE_GRAPH_BOUNDARY'


def stream_commitment(records):
    digest = hashlib.sha256()
    for record in records:
        digest.update(record)
    return digest.hexdigest()


class GraphAggregateGeneratorSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which('node')
        if cls.node is None:
            raise unittest.SkipTest('Node.js is unavailable; generator safety tests cannot run')
        spec = json.loads(CASES.read_text(encoding='utf-8'))
        cls.generator = (CASES.parent / spec['generator']).resolve()

    def invoke_check(self, destination):
        return subprocess.run(
            [
                self.node,
                str(self.generator),
                '--check-output-only',
                str(destination),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def assert_rejected(self, destination, message):
        completed = self.invoke_check(destination)
        self.assertNotEqual(0, completed.returncode)
        self.assertIn(message, completed.stderr)

    def test_rejects_relative_destination(self):
        self.assert_rejected(
            Path('relative-aggregate-output'),
            'output directory must be an absolute path',
        )

    def test_rejects_non_normalized_destination(self):
        with tempfile.TemporaryDirectory(prefix='aural-generator-parent-') as parent:
            destination = str(Path(parent) / 'unused' / '..' / 'fresh-output')
            self.assert_rejected(
                destination,
                'output directory must already be safely normalized',
            )

    def test_rejects_existing_directory(self):
        with tempfile.TemporaryDirectory(prefix='aural-generator-parent-') as parent:
            existing = Path(parent) / 'existing'
            existing.mkdir()
            self.assert_rejected(existing, 'output directory must not already exist')

    def test_rejects_destination_inside_repository(self):
        destination = ROOT / '.aggregate-generator-safety-probe'
        self.assertFalse(destination.exists())
        self.assert_rejected(
            destination,
            'output directory must not be inside the repository checkout',
        )
        self.assertFalse(destination.exists())

    def test_rejects_destination_outside_os_temporary_directory(self):
        destination = Path(ROOT.anchor) / 'aural-aggregate-generator-outside-temp-probe'
        self.assertFalse(destination.exists())
        self.assert_rejected(
            destination,
            'output directory must be under the operating system temporary directory',
        )
        self.assertFalse(destination.exists())

    def test_rejects_symlink_or_junction_redirection_when_supported(self):
        with tempfile.TemporaryDirectory(prefix='aural-generator-parent-') as parent:
            redirect = Path(parent) / 'redirect'
            try:
                redirect.symlink_to(ROOT.parent, target_is_directory=True)
            except OSError as symlink_error:
                junction = subprocess.run(
                    [
                        self.node,
                        '-e',
                        "require('node:fs').symlinkSync(process.argv[1], "
                        "process.argv[2], 'junction')",
                        str(ROOT.parent),
                        str(redirect),
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if junction.returncode != 0:
                    self.skipTest(
                        'directory symlinks/junctions are unavailable: '
                        f'{symlink_error}; {junction.stderr.strip()}',
                    )
            try:
                self.assert_rejected(
                    redirect / 'fresh-output',
                    'output directory parent',
                )
            finally:
                if redirect.is_symlink():
                    redirect.unlink()
                else:
                    redirect.rmdir()

    def test_accepts_fresh_temporary_destination_without_large_generation(self):
        with tempfile.TemporaryDirectory(prefix='aural-generator-parent-') as parent:
            destination = Path(parent) / 'fresh-output'
            completed = self.invoke_check(destination)
            self.assertEqual(
                0, completed.returncode,
                f'stdout: {completed.stdout}\nstderr: {completed.stderr}',
            )
            self.assertTrue(destination.is_dir())
            self.assertEqual([], list(destination.iterdir()))


class GraphAggregateByteLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get(OPT_IN_VARIABLE) != '1':
            raise unittest.SkipTest(
                f'large aggregate-boundary cases require {OPT_IN_VARIABLE}=1; '
                'a full graph conformance run is incomplete without them',
            )
        cls.node = shutil.which('node')
        if cls.node is None:
            raise unittest.SkipTest(
                'Node.js is unavailable; cross-language aggregate-boundary '
                'conformance is incomplete',
            )
        cls.spec = json.loads(CASES.read_text(encoding='utf-8'))
        case_ids = [test_case['id'] for test_case in cls.spec['cases']]
        if len(case_ids) != 2 or set(case_ids) != REQUIRED_CASE_IDS:
            raise AssertionError(
                'aggregate-boundary inventory must contain exactly the two required IDs',
            )

    def test_python_and_node_enforce_exact_aggregate_boundary(self):
        with tempfile.TemporaryDirectory(prefix='aural-aggregate-boundary-') as temporary:
            temporary_parent = Path(temporary)
            temporary_path = temporary_parent / 'fixture'
            generator = (CASES.parent / self.spec['generator']).resolve()
            generated = subprocess.run(
                [self.node, str(generator), str(temporary_path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=240,
                check=False,
            )
            self.assertEqual(
                0, generated.returncode,
                f'fixture generation failed\nstdout: {generated.stdout}'
                f'\nstderr: {generated.stderr}',
            )
            descriptor_path = temporary_path / 'fixture.json'
            descriptor = json.loads(descriptor_path.read_text(encoding='utf-8'))
            self.assertEqual(self.spec['source_sha256'], descriptor['source_sha256'])
            generated_by_id = {
                test_case['id']: test_case for test_case in descriptor['cases']
            }
            self.assertEqual(REQUIRED_CASE_IDS, set(generated_by_id))
            at_paths = generated_by_id['H-aggregate-bytes-at-limit']['record_paths']
            over_paths = generated_by_id['N-aggregate-bytes-over-limit']['record_paths']
            self.assertEqual(at_paths[:-1], over_paths[:-1])

            key_path = (CASES.parent / self.spec['public_key']).resolve()
            key = key_path.read_bytes()
            expected_by_id = {
                test_case['id']: test_case for test_case in self.spec['cases']
            }
            common_paths = generated_by_id['H-aggregate-bytes-at-limit']['record_paths'][:-1]
            common_records = [
                (temporary_path / relative).read_bytes() for relative in common_paths
            ]
            python_evidence = {}

            for case_id in (
                    'H-aggregate-bytes-at-limit',
                    'N-aggregate-bytes-over-limit'):
                expected = expected_by_id[case_id]
                generated_case = generated_by_id[case_id]
                tail = (temporary_path / generated_case['record_paths'][-1]).read_bytes()
                records = [*common_records, tail]
                evidence = {
                    'record_count': len(records),
                    'aggregate_event_bytes': sum(map(len, records)),
                    'maximum_event_bytes': max(map(len, records)),
                    'event_byte_lengths': [len(record) for record in records],
                    'ordered_input_sha256': stream_commitment(records),
                    'record_sha256': [hashlib.sha256(record).hexdigest()
                                      for record in records],
                }
                self.assertEqual(expected['record_count'], evidence['record_count'])
                self.assertEqual(
                    expected['aggregate_event_bytes'], evidence['aggregate_event_bytes'],
                )
                self.assertEqual(
                    expected['maximum_event_bytes'], evidence['maximum_event_bytes'],
                )
                layout = self.spec['record_layout']
                self.assertEqual(
                    [layout['shared_record_bytes']] * layout['shared_record_count']
                    + [expected['tail_event_bytes']],
                    evidence['event_byte_lengths'],
                )
                self.assertEqual(
                    expected['ordered_input_sha256'], evidence['ordered_input_sha256'],
                )
                self.assertEqual(
                    generated_case['ordered_input_sha256'],
                    evidence['ordered_input_sha256'],
                )
                self.assertEqual(
                    generated_case['record_sha256'], evidence['record_sha256'],
                )
                self.assertTrue(all(
                    0 < len(record) <= provenance.MAX_EVENT_BYTES for record in records
                ))

                try:
                    result = provenance.verify_signed_event_graph(records, [key])
                except provenance.ProvenanceVerificationError as error:
                    evidence['accepted'] = False
                    evidence['error'] = {
                        'category': error.category.value,
                        'stage': error.stage.value,
                        'message': str(error),
                    }
                else:
                    evidence['accepted'] = True
                    evidence['result'] = result

                self.assertIs(
                    expected['expected']['accepted'], evidence['accepted'],
                    f'{case_id}: Python acceptance differs',
                )
                if evidence['accepted']:
                    result = evidence['result']
                    self.assertEqual(len(records), len(result.events))
                    self.assertEqual(0, result.duplicate_signed_records)
                    self.assertEqual(1, result.maximum_depth)
                    self.assertTrue(all(
                        event.status is provenance.VerificationStatus.SIGNATURE_VALID
                        and event.declared_parent_count == 0
                        for event in result.events
                    ))
                    evidence['distinct_event_id_count'] = len({
                        event.event_id for event in result.events
                    })
                    evidence['all_event_signatures_valid'] = True
                else:
                    self.assertEqual(
                        expected['expected']['error'], evidence['error'],
                        f'{case_id}: Python aggregate-limit error differs',
                    )
                    verified = [
                        provenance.verify_signed_event(record, [key])
                        for record in records
                    ]
                    evidence['distinct_event_id_count'] = len({
                        event.event_id for event in verified
                    })
                    evidence['all_event_signatures_valid'] = all(
                        event.status is provenance.VerificationStatus.SIGNATURE_VALID
                        for event in verified
                    )
                self.assertEqual(len(records), evidence['distinct_event_id_count'])
                self.assertIs(True, evidence['all_event_signatures_valid'])
                python_evidence[case_id] = evidence

            node = subprocess.run(
                [self.node, str(NODE_ADAPTER), str(CASES), str(descriptor_path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=240,
                check=False,
            )
            self.assertEqual(
                0, node.returncode,
                f'Node adapter failed\nstdout: {node.stdout}\nstderr: {node.stderr}',
            )
            node_cases = json.loads(node.stdout)['cases']
            self.assertEqual(REQUIRED_CASE_IDS, set(node_cases))
            for case_id in REQUIRED_CASE_IDS:
                expected = expected_by_id[case_id]
                python_case = python_evidence[case_id]
                node_case = node_cases[case_id]
                for field in (
                        'record_count', 'aggregate_event_bytes', 'maximum_event_bytes',
                        'event_byte_lengths', 'ordered_input_sha256', 'record_sha256',
                        'distinct_event_id_count', 'all_event_signatures_valid'):
                    self.assertEqual(
                        python_case[field], node_case[field],
                        f'{case_id}: Python and Node {field} evidence differs',
                    )
                self.assertIs(expected['expected']['accepted'], node_case['accepted'])
                if node_case['accepted']:
                    self.assertEqual(65, node_case['result']['recordCount'])
                    self.assertEqual(0, node_case['result']['duplicateRecordCount'])
                    self.assertEqual(1, node_case['result']['maximumDepth'])
                    self.assertEqual('valid', node_case['result']['signatureVerification'])
                else:
                    self.assertEqual(
                        expected['expected']['error'],
                        {name: node_case['error'][name]
                         for name in ('category', 'stage', 'message')},
                    )


if __name__ == '__main__':
    unittest.main()
