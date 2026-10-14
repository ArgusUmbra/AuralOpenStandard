import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest import mock

from aural import provenance


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'fixtures' / 'provenance'
PACKAGE_CORPUS = ROOT / 'tests' / 'fixtures' / 'conformance'

try:
    import cryptography
except ImportError:
    cryptography = None


@unittest.skipUnless(cryptography is not None, 'Python cryptography is not installed')
class ProvenanceCryptographicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads((CORPUS / 'expected.json').read_text(encoding='utf-8'))
        cls.key_raw = (CORPUS / 'valid-key.json').read_bytes()
        key = json.loads(cls.key_raw)
        cls.public_key = base64.urlsafe_b64decode(key['public_key'] + '=')

    def verify_file(self, name):
        return provenance.verify_signed_event((CORPUS / name).read_bytes(), [self.key_raw])

    def canonical_record(self, document):
        return provenance._jcs_text(
            document, provenance.VerificationStage.RECORD,
        ).encode('utf-8')

    def assert_signature_error(self, operation, category=provenance.ErrorCategory.SIGNATURE):
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            operation()
        self.assertEqual(category, raised.exception.category)
        self.assertEqual(provenance.VerificationStage.SIGNATURE, raised.exception.stage)

    def test_all_three_positive_vectors_and_result_semantics(self):
        positive = [case for case in self.expected['cases'].values()
                    if case['outcome'] == 'accept']
        self.assertEqual(3, len(positive))
        for case in positive:
            with self.subTest(event=case['event']):
                raw = (CORPUS / case['event']).read_bytes()
                assertion = json.loads(raw)['assertion']
                result = provenance.verify_signed_event(raw, [self.key_raw])
                self.assertEqual(provenance.VerificationStatus.SIGNATURE_VALID, result.status)
                self.assertEqual(assertion['event_id'], result.event_id)
                self.assertEqual(assertion['evidence_id'], result.evidence_id)
                self.assertEqual(assertion['signing_key_id'], result.signing_key_id)
                self.assertEqual(case['signed_event_digest'], result.signed_event_sha256)
                self.assertEqual(provenance.AssetIntegrityStatus.NOT_CHECKED,
                                 result.asset_integrity)
                self.assertEqual(provenance.InvestigatorIdentityStatus.NOT_ESTABLISHED,
                                 result.investigator_identity)
                self.assertEqual(provenance.KeyTrustStatus.NOT_EVALUATED, result.key_trust)
                self.assertEqual(provenance.TimeAssuranceStatus.CLAIMED_ONLY,
                                 result.time_assurance)
                self.assertEqual(provenance.HistoryCompletenessStatus.NOT_ESTABLISHED,
                                 result.history_completeness)
                self.assertEqual(len(assertion['parents']), result.declared_parent_count)

    def test_provider_gate_is_exactly_the_existing_13_vector_corpus_and_cached(self):
        vectors = json.loads(
            (CORPUS / 'ed25519-adversarial.json').read_text(encoding='utf-8'),
        )['vectors']
        embedded = [
            (expected, public_key, message, signature)
            for expected, public_key, message, signature
            in provenance._ED25519_PROVIDER_VECTORS
        ]
        fixture = [
            (vector['expected'], vector['public_key'], vector['message'], vector['signature'])
            for vector in vectors
        ]
        self.assertEqual(13, len(embedded))
        self.assertEqual(fixture, embedded)

        provenance._provider_capability.cache_clear()
        first = provenance._provider_capability()
        second = provenance._provider_capability()
        self.assertIsNone(first[2])
        self.assertIs(first, second)
        cache = provenance._provider_capability.cache_info()
        self.assertEqual(1, cache.misses)
        self.assertEqual(1, cache.hits)

    def test_application_verifier_matches_all_13_adversarial_vectors(self):
        vectors = json.loads(
            (CORPUS / 'ed25519-adversarial.json').read_text(encoding='utf-8'),
        )['vectors']
        for vector in vectors:
            operation = lambda vector=vector: provenance._verify_ed25519_profile(
                bytes.fromhex(vector['public_key']), bytes.fromhex(vector['message']),
                bytes.fromhex(vector['signature']),
            )
            with self.subTest(vector=vector['name']):
                if vector['expected']:
                    operation()
                else:
                    with self.assertRaises(provenance.ProvenanceVerificationError):
                        operation()

    def test_invalid_signature_and_wrong_public_key(self):
        case = self.expected['cases']['invalid-signature']
        self.assert_signature_error(lambda: self.verify_file(case['event']))

        record = json.loads((CORPUS / 'valid-original-acquired.json').read_bytes())
        signature = base64.urlsafe_b64decode(record['signature'] + '==')
        assertion = self.canonical_record(record['assertion'])
        wrong_key = bytes.fromhex(
            '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
        )
        self.assert_signature_error(lambda: provenance._verify_ed25519_profile(
            wrong_key, provenance.SIGNATURE_DOMAIN + assertion, signature,
        ))

    def test_small_order_noncanonical_points_and_scalar_bounds(self):
        vectors = {vector['name']: vector for vector in json.loads(
            (CORPUS / 'ed25519-adversarial.json').read_text(encoding='utf-8'),
        )['vectors']}
        cases = {
            'identity-key-identity-r': provenance.ErrorCategory.PUBLIC_KEY,
            'small-a-mixed-r': provenance.ErrorCategory.PUBLIC_KEY,
            'mixed-a-small-r': provenance.ErrorCategory.SIGNATURE,
            'noncanonical-r-wire-hash': provenance.ErrorCategory.SIGNATURE,
            'noncanonical-a-wire-hash': provenance.ErrorCategory.PUBLIC_KEY,
            'scalar-l-plus': provenance.ErrorCategory.SIGNATURE,
            'scalar-high': provenance.ErrorCategory.SIGNATURE,
        }
        for name, category in cases.items():
            vector = vectors[name]
            with self.subTest(vector=name):
                self.assert_signature_error(
                    lambda vector=vector: provenance._verify_ed25519_profile(
                        bytes.fromhex(vector['public_key']), bytes.fromhex(vector['message']),
                        bytes.fromhex(vector['signature']),
                    ),
                    category,
                )

    def test_wrong_domain_separator_is_rejected(self):
        record = json.loads((CORPUS / 'valid-original-acquired.json').read_bytes())
        assertion = self.canonical_record(record['assertion'])
        signature = base64.urlsafe_b64decode(record['signature'] + '==')
        self.assert_signature_error(lambda: provenance._verify_ed25519_profile(
            self.public_key, b'AURAL-PROVENANCE-EVENT-V0\x00' + assertion, signature,
        ))

    def test_every_mutated_covered_assertion_field_is_rejected(self):
        original = json.loads((CORPUS / 'valid-original-acquired.json').read_bytes())

        def extension(document):
            document['assertion']['extensions'] = {'urn:test:covered': {'value': 1}}

        def evidence_id(document):
            document['assertion']['evidence_id'] = (
                'urn:uuid:baaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
            )

        def event_id(document):
            document['assertion']['event_id'] = (
                'urn:uuid:21111111-2222-4333-8444-555555555555'
            )

        def manifest_digest(document):
            document['assertion']['subject']['manifest_sha256'] = '0' * 64

        def wav_digest(document):
            document['assertion']['subject']['original']['sha256'] = '0' * 64

        def claimed_timestamp(document):
            document['assertion']['claims']['claimed_times'][0]['value'] = (
                '2026-10-13T17:59:59Z'
            )

        for name, mutation in (
                ('extension', extension),
                ('evidence_id', evidence_id),
                ('event_id', event_id),
                ('manifest_digest', manifest_digest),
                ('wav_digest', wav_digest),
                ('claimed_timestamp', claimed_timestamp)):
            document = copy.deepcopy(original)
            mutation(document)
            raw = self.canonical_record(document)
            with self.subTest(field=name):
                self.assert_signature_error(
                    lambda raw=raw: provenance.verify_signed_event(raw, [self.key_raw]),
                )

        child = json.loads((CORPUS / 'valid-received-with-parent.json').read_bytes())
        child['assertion']['parents'][0]['signed_event_digest']['value'] = '0' * 64
        raw = self.canonical_record(child)
        self.assert_signature_error(
            lambda: provenance.verify_signed_event(raw, [self.key_raw]),
        )

    def test_signed_event_digest_reproduces_all_golden_values(self):
        for case in self.expected['cases'].values():
            if case['outcome'] != 'accept':
                continue
            raw = (CORPUS / case['event']).read_bytes()
            expected = hashlib.sha256(provenance.SIGNED_EVENT_DOMAIN + raw).hexdigest()
            self.assertEqual(case['signed_event_digest'], expected)
            self.assertEqual(expected, provenance.verify_signed_event(
                raw, [self.key_raw],
            ).signed_event_sha256)

    def test_provider_failure_is_stable_and_fails_closed(self):
        raw = (CORPUS / 'valid-original-acquired.json').read_bytes()
        with mock.patch.object(
                provenance, '_provider_capability',
                return_value=(None, None, 'test provider failure')):
            self.assert_signature_error(
                lambda: provenance.verify_signed_event(raw, [self.key_raw]),
                provenance.ErrorCategory.PROVIDER_UNAVAILABLE,
            )

    def test_explicit_package_path_verifies_asset_binding(self):
        raw = (CORPUS / 'valid-original-acquired.json').read_bytes()
        result = provenance.verify_signed_event(
            raw, [self.key_raw], package_path=PACKAGE_CORPUS / 'valid-unicode.aural',
        )
        self.assertEqual(provenance.AssetIntegrityStatus.VERIFIED, result.asset_integrity)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_python_results_match_independent_node_verifier(self):
        positive = [case for case in self.expected['cases'].values()
                    if case['outcome'] == 'accept']
        validator_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        cases = [{'event': str(CORPUS / case['event']),
                  'digest': case['signed_event_digest']} for case in positive]
        script = (
            "import {readFile} from 'node:fs/promises';"
            f"import {{verifySignedEvent}} from {json.dumps(validator_uri)};"
            f"const cases={json.dumps(cases)};"
            f"const key=await readFile({json.dumps(str(CORPUS / 'valid-key.json'))});"
            "const results=[];for(const item of cases){const event=await readFile(item.event);"
            "const result=verifySignedEvent(event,[key]);results.push(result.signed_event_sha256);}"
            "console.log(JSON.stringify(results));"
        )
        completed = subprocess.run(
            ['node', '--input-type=module', '--eval', script],
            capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual([case['digest'] for case in cases], json.loads(completed.stdout))


class ProvenanceProviderAbsenceTests(unittest.TestCase):
    def test_provider_unavailable_category_is_public(self):
        self.assertEqual('provider_unavailable', provenance.ErrorCategory.PROVIDER_UNAVAILABLE.value)


if __name__ == '__main__':
    unittest.main()
