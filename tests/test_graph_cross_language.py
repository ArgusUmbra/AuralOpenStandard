import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from aural import provenance


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'tests' / 'fixtures' / 'graph_conformance' / 'cases.json'
NODE_ADAPTER = ROOT / 'tests' / 'graph_conformance_node_adapter.mjs'
REQUIRED_POSITIVE_CASE_IDS = frozenset({
    'A-signed-root-no-package',
    'B-signed-root-matching-package',
    'C-parent-child',
    'D-identical-duplicates',
    'E-independent-roots',
    'F-multi-parent-history',
    'G-input-order-independence',
})
REQUIRED_NEGATIVE_CASE_IDS = frozenset({
    'N01-invalid-ed25519-signature',
    'N02-missing-declared-parent',
    'N03-parent-digest-mismatch',
    'N04-unrelated-valid-package',
    'N05-corrupted-original-audio',
    'N06-invalid-manifest',
    'N07-invalid-zip-structure',
    'N08-missing-signing-key',
    'N09-malformed-public-key',
    'N10-incorrect-key-id',
    'N11-duplicate-public-key-id',
    'N12-invalid-ed25519-profile',
})
REQUIRED_RESOURCE_CASE_IDS = frozenset({
    'H-parent-fanout-64',
    'I-graph-depth-256',
    'N13-parent-fanout-65',
    'N14-graph-depth-257',
    'N15-competing-malformed-forward',
    'N16-competing-malformed-reverse',
})
REQUIRED_CASE_IDS = (
    REQUIRED_POSITIVE_CASE_IDS | REQUIRED_NEGATIVE_CASE_IDS | REQUIRED_RESOURCE_CASE_IDS
)
SIGNED_EVENT_DIGEST_DOMAIN = b'AURAL-SIGNED-EVENT-V1\0'

# This is the deliberately narrow public-API mapping. Python aggregate fields
# are snake_case while Node aggregate fields are camelCase. Event result fields
# already share snake_case names. The three derived Python values below use
# direct public result claims; none is inferred from signature validity.
AGGREGATE_FIELD_MAP = {
    'status': ('status', 'status'),
    'declared_parent_closure': (
        'declared_parent_closure', 'declaredParentClosure',
    ),
    'history_completeness': ('history_completeness', 'historyCompleteness'),
    'package_integrity': (
        'uniform events[].asset_integrity', 'packageIntegrity',
    ),
    'unique_event_count': ('len(events)', 'recordCount'),
    'duplicate_input_count': (
        'duplicate_signed_records', 'duplicateRecordCount',
    ),
    'declared_parent_count': (
        'sum(events[].declared_parent_count)', 'declaredParentCount',
    ),
    'maximum_depth': ('maximum_depth', 'maximumDepth'),
    'ordered_event_ids': ('events[].event_id', 'eventIds'),
}

# Node exposes these redundant or more granular aggregate claims without a
# standalone Python field. They are asserted against independent expectations
# instead of being silently discarded by normalization.
NODE_ONLY_AGGREGATE_FIELDS = {
    'verificationStatus': 'same graph-consistency meaning as Python status',
    'parentResolution': 'represented by Python declared_parent_closure',
    'signatureVerification': 'represented by Python per-event status values',
    'subjectBinding': 'represented by Python per-event asset_integrity after binding',
}

EVENT_FIELDS = {
    'event_id': 'event_id',
    'signed_event_sha256': 'signed_event_sha256',
    'signature_verification': 'status',
    'package_integrity': 'asset_integrity',
    'parent_count': 'declared_parent_count',
    'investigator_identity': 'investigator_identity',
    'key_trust': 'key_trust',
    'time_assurance': 'time_assurance',
    'history_completeness': 'history_completeness',
}


def validate_case_inventory(cases):
    if not isinstance(cases, list) or not cases:
        raise AssertionError('graph-conformance case inventory must be a nonempty list')

    case_ids = []
    for index, test_case in enumerate(cases):
        if not isinstance(test_case, dict) or not isinstance(test_case.get('id'), str):
            raise AssertionError(
                f'graph-conformance case at index {index} must have a string id',
            )
        case_ids.append(test_case['id'])

    duplicate_ids = sorted({case_id for case_id in case_ids if case_ids.count(case_id) > 1})
    actual_ids = set(case_ids)
    missing_ids = sorted(REQUIRED_CASE_IDS - actual_ids)
    unexpected_ids = sorted(actual_ids - REQUIRED_CASE_IDS)
    problems = []
    if duplicate_ids:
        problems.append(f'duplicate IDs: {duplicate_ids}')
    if missing_ids:
        problems.append(f'missing IDs: {missing_ids}')
    if unexpected_ids:
        problems.append(f'unexpected IDs: {unexpected_ids}')
    if problems:
        raise AssertionError(
            'invalid graph-conformance case inventory; ' + '; '.join(problems),
        )


def enum_value(value):
    return value.value if hasattr(value, 'value') else value


def uniform(values):
    distinct = sorted(set(values))
    if len(distinct) == 1:
        return distinct[0]
    return {'non_uniform_values': distinct}


def normalize_python(result):
    events = []
    for event in result.events:
        events.append({
            common: enum_value(getattr(event, python_name))
            for common, python_name in EVENT_FIELDS.items()
        })
    return {
        'accepted': True,
        'status': enum_value(result.status),
        'declared_parent_closure': enum_value(result.declared_parent_closure),
        'history_completeness': enum_value(result.history_completeness),
        'package_integrity': uniform([
            event['package_integrity'] for event in events
        ]),
        'unique_event_count': len(events),
        'duplicate_input_count': result.duplicate_signed_records,
        'declared_parent_count': sum(event['parent_count'] for event in events),
        'maximum_depth': result.maximum_depth,
        'ordered_event_ids': [event['event_id'] for event in events],
        'events': events,
    }


def normalize_node(result):
    events = []
    for event in result['events']:
        events.append({
            common: event[node_name]
            for common, node_name in EVENT_FIELDS.items()
        })
    return {
        'accepted': True,
        'status': result['status'],
        'declared_parent_closure': result['declaredParentClosure'],
        'history_completeness': result['historyCompleteness'],
        'package_integrity': result['packageIntegrity'],
        'unique_event_count': result['recordCount'],
        'duplicate_input_count': result['duplicateRecordCount'],
        'declared_parent_count': result['declaredParentCount'],
        'maximum_depth': result['maximumDepth'],
        'ordered_event_ids': result['eventIds'],
        'events': events,
    }


class GraphCrossLanguageConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
        cls.base = MANIFEST.parent
        cls.cases = cls.manifest.get('cases')
        validate_case_inventory(cls.cases)
        cls.events = cls.manifest['events']
        cls.bundles = {}
        for alias, fixture in cls.manifest.get('bundles', {}).items():
            relative = Path(fixture['path'])
            if relative.is_absolute():
                raise AssertionError(f'{alias}: resource bundle path must be relative')
            path = cls.base / relative
            compressed = path.read_bytes()
            actual_sha256 = hashlib.sha256(compressed).hexdigest()
            if actual_sha256 != fixture['sha256']:
                raise AssertionError(
                    f'{alias}: resource bundle SHA-256 does not match manifest pin',
                )
            document = json.loads(gzip.decompress(compressed))
            if document.get('schema') != 'org.aural.graph-resource-fixtures' \
                    or document.get('schema_version') != '1' \
                    or not isinstance(document.get('collections'), dict):
                raise AssertionError(f'{alias}: invalid graph-resource fixture bundle')
            cls.bundles[alias] = document
        cls.node = shutil.which('node')

    def fixture_path(self, relative):
        path = Path(relative)
        self.assertFalse(path.is_absolute(), f'fixture path must be relative: {path}')
        return (self.base / path).resolve()

    def case_inputs(self, test_case):
        if 'resource_bundle' in test_case:
            selection = test_case['resource_bundle']
            bundle = self.bundles[selection['bundle']]
            encoded = bundle['collections'][selection['collection']]
            self.assertIsInstance(encoded, list)
            records = [record.encode('utf-8') for record in encoded]
        else:
            records = [
                self.fixture_path(self.events[alias]['path']).read_bytes()
                for alias in test_case['signed_events']
            ]
        keys = [
            self.fixture_path(self.manifest['public_keys'][alias]).read_bytes()
            for alias in test_case['public_keys']
        ]
        package = None
        package_sha256 = None
        if 'package' in test_case:
            package_fixture = self.manifest['packages'][test_case['package']]
            package = self.fixture_path(package_fixture['path'])
            package_sha256 = hashlib.sha256(package.read_bytes()).hexdigest()
            self.assertEqual(
                package_fixture['sha256'], package_sha256,
                f"{test_case['id']}: package fixture SHA-256 does not match manifest pin",
            )
        return records, keys, package, package_sha256

    def expected_result(self, test_case):
        expected = dict(test_case['expected'])
        if not expected['accepted']:
            return expected
        event_source = expected.pop('ordered_event_source', None)
        if event_source == 'resource_bundle_order':
            records, _keys, _package, _package_sha256 = self.case_inputs(test_case)
            fixtures = []
            for raw in records:
                assertion = json.loads(raw)['assertion']
                fixtures.append({
                    'event_id': assertion['event_id'],
                    'signed_event_sha256': hashlib.sha256(
                        SIGNED_EVENT_DIGEST_DOMAIN + raw,
                    ).hexdigest(),
                    'parent_count': len(assertion['parents']),
                    'signature_verification': 'signature_valid',
                    'investigator_identity': 'not_established',
                    'key_trust': 'not_evaluated',
                    'time_assurance': 'claimed_only',
                    'history_completeness': 'not_established',
                })
        else:
            ordered_aliases = expected.pop('ordered_events')
            fixtures = [self.events[alias] for alias in ordered_aliases]
        expected['ordered_event_ids'] = [fixture['event_id'] for fixture in fixtures]
        expected['events'] = [{
            common: (expected['package_integrity']
                     if common == 'package_integrity' else fixture[common])
            for common in EVENT_FIELDS
        } for fixture in fixtures]
        return expected

    def assert_python_case_claims(self, test_case, records, keys):
        claims = test_case.get('claims', {})
        if claims.get('all_event_signatures_valid'):
            for index, record in enumerate(records):
                result = provenance.verify_signed_event(record, keys)
                self.assertEqual(
                    provenance.VerificationStatus.SIGNATURE_VALID,
                    result.status,
                    f"{test_case['id']}: record {index} is not genuinely signed",
                )

    def verify_python(self, test_case):
        records, keys, package, package_sha256 = self.case_inputs(test_case)
        try:
            result = provenance.verify_signed_event_graph(
                records, keys, package_path=package,
            )
        except provenance.ProvenanceVerificationError as error:
            normalized = {
                'accepted': False,
                'error': {
                    'category': error.category.value,
                    'stage': error.stage.value,
                },
            }
        else:
            normalized = normalize_python(result)
        return records, keys, package_sha256, normalized

    def mismatch_lines(self, case_id, python_result, node_result, expected):
        lines = []

        def compare(path, python_value, node_value, expected_value):
            if isinstance(expected_value, dict):
                keys = set(expected_value)
                if not isinstance(python_value, dict) or not isinstance(node_value, dict):
                    lines.append((path, python_value, node_value, expected_value))
                    return
                keys |= set(python_value) | set(node_value)
                for key in sorted(keys):
                    compare(
                        f'{path}.{key}' if path else key,
                        python_value.get(key, '<missing>'),
                        node_value.get(key, '<missing>'),
                        expected_value.get(key, '<unexpected>'),
                    )
                return
            if isinstance(expected_value, list):
                if not isinstance(python_value, list) or not isinstance(node_value, list):
                    lines.append((path, python_value, node_value, expected_value))
                    return
                maximum = max(len(expected_value), len(python_value), len(node_value))
                for index in range(maximum):
                    compare(
                        f'{path}[{index}]',
                        python_value[index] if index < len(python_value) else '<missing>',
                        node_value[index] if index < len(node_value) else '<missing>',
                        expected_value[index] if index < len(expected_value) else '<unexpected>',
                    )
                return
            if python_value != expected_value or node_value != expected_value \
                    or python_value != node_value:
                lines.append((path, python_value, node_value, expected_value))

        compare('', python_result, node_result, expected)
        return [
            f'case={case_id} field={field} '
            f'python={json.dumps(python_value, sort_keys=True)} '
            f'node={json.dumps(node_value, sort_keys=True)} '
            f'expected={json.dumps(expected_value, sort_keys=True)}'
            for field, python_value, node_value, expected_value in lines
        ]

    def assert_node_only_claims(self, test_case, result):
        expected = test_case['expected']
        self.assertEqual(expected['status'], result['verificationStatus'])
        self.assertEqual('resolved', result['parentResolution'])
        self.assertEqual('valid', result['signatureVerification'])
        if expected['package_integrity'] == 'verified':
            self.assertEqual('verified', result['subjectBinding'])
        else:
            self.assertNotIn('subjectBinding', result)

    def test_inventory_rejects_empty_case_list(self):
        with self.assertRaisesRegex(AssertionError, 'must be a nonempty list'):
            validate_case_inventory([])

    def test_inventory_rejects_missing_required_case(self):
        cases = [
            test_case for test_case in self.cases
            if test_case['id'] != 'C-parent-child'
        ]
        with self.assertRaisesRegex(AssertionError, r"missing IDs: \['C-parent-child'\]"):
            validate_case_inventory(cases)

    def test_inventory_rejects_duplicate_case_id(self):
        cases = [*self.cases, dict(self.cases[0])]
        with self.assertRaisesRegex(
                AssertionError, r"duplicate IDs: \['A-signed-root-no-package'\]"):
            validate_case_inventory(cases)

    def test_inventory_rejects_unexpected_case_id(self):
        cases = [*self.cases, {'id': 'Z-unexpected-case'}]
        with self.assertRaisesRegex(
                AssertionError, r"unexpected IDs: \['Z-unexpected-case'\]"):
            validate_case_inventory(cases)

    def test_python_results_match_independent_expectations(self):
        for test_case in self.cases:
            with self.subTest(case=test_case['id']):
                records, keys, _package_sha256, actual = self.verify_python(test_case)
                self.assert_python_case_claims(test_case, records, keys)
                expected = self.expected_result(test_case)
                diagnostics = self.mismatch_lines(
                    test_case['id'], actual, actual, expected,
                )
                self.assertFalse(diagnostics, '\n'.join(diagnostics))

    def test_node_and_python_independently_match_shared_expectations(self):
        if self.node is None:
            self.skipTest('Node.js is unavailable; Python expectations still ran')
        completed = subprocess.run(
            [self.node, str(NODE_ADAPTER), str(MANIFEST)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(
            0, completed.returncode,
            f'Node adapter failed\nstdout: {completed.stdout}\nstderr: {completed.stderr}',
        )
        payload = json.loads(completed.stdout)
        expected_case_ids = {case['id'] for case in self.cases}
        self.assertEqual(expected_case_ids, set(payload['cases']))

        python_by_id = {}
        node_by_id = {}
        all_diagnostics = []
        for test_case in self.cases:
            case_id = test_case['id']
            with self.subTest(case=case_id):
                records, keys, package_sha256, python_result = self.verify_python(test_case)
                node_case = payload['cases'][case_id]
                self.assert_python_case_claims(test_case, records, keys)
                if test_case.get('claims', {}).get('all_event_signatures_valid'):
                    self.assertIs(
                        True, node_case.get('all_event_signatures_valid'),
                        f'{case_id}: Node did not validate every fixture signature',
                    )
                self.assertEqual(
                    [hashlib.sha256(raw).hexdigest() for raw in records],
                    node_case['event_input_sha256'],
                    f'{case_id}: verifier event input bytes differ',
                )
                self.assertEqual(
                    [hashlib.sha256(raw).hexdigest() for raw in keys],
                    node_case['key_input_sha256'],
                    f'{case_id}: verifier public-key input bytes differ',
                )
                if package_sha256 is None:
                    self.assertNotIn('package_input_sha256', node_case)
                else:
                    self.assertEqual(
                        package_sha256, node_case.get('package_input_sha256'),
                        f'{case_id}: verifier package input bytes differ',
                    )
                if 'error' in node_case:
                    node_result = {
                        'accepted': False,
                        'error': {
                            'category': node_case['error']['category'],
                            'stage': node_case['error']['stage'],
                        },
                    }
                    expected = self.expected_result(test_case)
                    all_diagnostics.extend(self.mismatch_lines(
                        case_id, python_result, node_result, expected,
                    ))
                    python_by_id[case_id] = python_result
                    node_by_id[case_id] = node_result
                    continue
                node_result = normalize_node(node_case['result'])
                expected = self.expected_result(test_case)
                if expected['accepted']:
                    self.assert_node_only_claims(test_case, node_case['result'])
                all_diagnostics.extend(self.mismatch_lines(
                    case_id, python_result, node_result, expected,
                ))
                python_by_id[case_id] = python_result
                node_by_id[case_id] = node_result

        for test_case in self.cases:
            equivalent_to = test_case.get('equivalent_to')
            if equivalent_to is not None:
                self.assertEqual(
                    python_by_id[equivalent_to],
                    python_by_id[test_case['id']],
                    f"Python {test_case['id']} differs from {equivalent_to}",
                )
                self.assertEqual(
                    node_by_id[equivalent_to],
                    node_by_id[test_case['id']],
                    f"Node {test_case['id']} differs from {equivalent_to}",
                )
        self.assertFalse(all_diagnostics, '\n'.join(all_diagnostics))


if __name__ == '__main__':
    unittest.main()
