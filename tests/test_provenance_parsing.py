import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from aural import provenance


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'fixtures' / 'provenance'
CRYPTO_OR_BINDING_CATEGORIES = {'signature', 'public_key', 'subject_binding'}


class ProvenanceParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads((CORPUS / 'expected.json').read_text(encoding='utf-8'))

    def verify_case(self, case):
        event = (CORPUS / case['event']).read_bytes()
        keys = [(CORPUS / name).read_bytes() for name in case['keys']]
        try:
            provenance.verify_signed_event(event, keys)
        except provenance.ProvenanceVerificationError as exc:
            return exc.category.value
        self.fail('2A verifier unexpectedly returned success')

    def assert_signature_pending(self, record, keys):
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            provenance.verify_signed_event(record, keys)
        self.assertEqual(provenance.ErrorCategory.NOT_IMPLEMENTED, raised.exception.category)
        self.assertEqual(provenance.VerificationStage.SIGNATURE, raised.exception.stage)

    def test_three_valid_records_pass_structure_and_key_resolution(self):
        cases = [case for case in self.expected['cases'].values() if case['outcome'] == 'accept']
        self.assertEqual(3, len(cases))
        for case in cases:
            with self.subTest(event=case['event']):
                self.assertEqual('not_implemented', self.verify_case(case))

    def test_structural_corpus_matches_reference_categories(self):
        compared = 0
        for name, case in self.expected['cases'].items():
            category = case.get('error_category')
            if case['outcome'] != 'reject' or category in CRYPTO_OR_BINDING_CATEGORIES:
                continue
            with self.subTest(case=name):
                self.assertEqual(category, self.verify_case(case))
            compared += 1
        self.assertEqual(36, compared)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_structural_outcomes_match_independent_node_validator(self):
        cases = []
        python_outcomes = []
        for case in self.expected['cases'].values():
            category = case.get('error_category')
            if case['outcome'] != 'reject' or category in CRYPTO_OR_BINDING_CATEGORIES:
                continue
            cases.append({
                'event': str(CORPUS / case['event']),
                'keys': [str(CORPUS / name) for name in case['keys']],
            })
            python_outcomes.append(self.verify_case(case))

        validator_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        script = (
            "import {readFile} from 'node:fs/promises';"
            f"import {{verifySignedEvent}} from {json.dumps(validator_uri)};"
            f"const cases={json.dumps(cases)};const outcomes=[];"
            "for(const item of cases){try{const event=await readFile(item.event);"
            "const keys=[];for(const path of item.keys)keys.push(await readFile(path));"
            "verifySignedEvent(event,keys);outcomes.push('accepted');}"
            "catch(error){outcomes.push(error.category??'internal');}}"
            "console.log(JSON.stringify(outcomes));"
        )
        completed = subprocess.run(
            ['node', '--input-type=module', '--eval', script],
            capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(python_outcomes, json.loads(completed.stdout))

    def test_depth_32_is_accepted_and_depth_33_is_rejected(self):
        event = json.loads((CORPUS / 'valid-original-acquired.json').read_bytes())
        key = (CORPUS / 'valid-key.json').read_bytes()
        value = 'leaf'
        for _ in range(29):
            value = [value]
        event['assertion']['extensions'] = {'urn:test:depth': value}
        depth_32 = provenance._jcs_text(
            event, provenance.VerificationStage.RECORD,
        ).encode('utf-8')
        self.assert_signature_pending(depth_32, [key])

        event['assertion']['extensions']['urn:test:depth'] = [value]
        depth_33 = provenance._jcs_text(
            event, provenance.VerificationStage.RECORD,
        ).encode('utf-8')
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            provenance.verify_signed_event(depth_33, [key])
        self.assertEqual(provenance.ErrorCategory.RESOURCE_LIMIT, raised.exception.category)

    def test_unicode_is_not_normalized(self):
        event = json.loads((CORPUS / 'valid-original-acquired.json').read_bytes())
        key = (CORPUS / 'valid-key.json').read_bytes()
        decomposed = 'e\u0301'
        event['assertion']['extensions'] = {'urn:test:unicode': decomposed}
        raw = provenance._jcs_text(event, provenance.VerificationStage.RECORD).encode('utf-8')
        self.assertIn(decomposed.encode('utf-8'), raw)
        self.assert_signature_pending(raw, [key])

    def test_all_supplied_keys_are_validated_before_selection(self):
        event = (CORPUS / 'valid-original-acquired.json').read_bytes()
        valid = (CORPUS / 'valid-key.json').read_bytes()
        malformed = (CORPUS / 'key-invalid-algorithm.json').read_bytes()
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            provenance.verify_signed_event(event, [valid, malformed])
        self.assertEqual(provenance.ErrorCategory.UNSUPPORTED_ALGORITHM, raised.exception.category)
        self.assertEqual(provenance.VerificationStage.KEY, raised.exception.stage)

    def test_unrelated_valid_key_is_accepted_but_not_selected(self):
        event = (CORPUS / 'valid-original-acquired.json').read_bytes()
        valid = (CORPUS / 'valid-key.json').read_bytes()
        public_key = bytes.fromhex(
            '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
        )
        encoded = base64.urlsafe_b64encode(public_key).rstrip(b'=').decode('ascii')
        unrelated = {
            'algorithm': 'Ed25519',
            'key_id': 'urn:aural:key:ed25519:' + hashlib.sha256(
                provenance.KEY_ID_DOMAIN + public_key,
            ).hexdigest(),
            'key_schema': 'org.aural.signing-key',
            'key_schema_version': '1',
            'public_key': encoded,
        }
        unrelated_raw = provenance._jcs_text(
            unrelated, provenance.VerificationStage.KEY,
        ).encode('utf-8')
        self.assert_signature_pending(event, [unrelated_raw, valid])

    def test_noncanonical_base64url_pad_bits_are_rejected(self):
        event = (CORPUS / 'valid-original-acquired.json').read_bytes()
        key = json.loads((CORPUS / 'valid-key.json').read_bytes())
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
        last = alphabet.index(key['public_key'][-1])
        key['public_key'] = key['public_key'][:-1] + alphabet[last + 1]
        raw = provenance._jcs_text(key, provenance.VerificationStage.KEY).encode('utf-8')
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            provenance.verify_signed_event(event, [raw])
        self.assertEqual(provenance.ErrorCategory.ENCODING, raised.exception.category)

    def test_key_records_use_the_same_strict_json_profile(self):
        event = (CORPUS / 'valid-original-acquired.json').read_bytes()
        key = (CORPUS / 'valid-key.json').read_bytes()
        duplicate = key.replace(
            b'{"algorithm":"Ed25519",',
            b'{"algorithm":"Ed25519","algorithm":"Ed25519",',
            1,
        )
        cases = [
            (key + b'\n', provenance.ErrorCategory.CANONICALIZATION),
            (b'\xef\xbb\xbf' + key, provenance.ErrorCategory.JSON_PROFILE),
            (duplicate, provenance.ErrorCategory.CANONICALIZATION),
        ]
        for raw, category in cases:
            with self.subTest(category=category):
                with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
                    provenance.verify_signed_event(event, [raw])
                self.assertEqual(category, raised.exception.category)
                self.assertEqual(provenance.VerificationStage.KEY, raised.exception.stage)

    def test_key_extensions_are_closed_and_critical_extensions_fail_closed(self):
        event = (CORPUS / 'valid-original-acquired.json').read_bytes()
        key = json.loads((CORPUS / 'valid-key.json').read_bytes())
        key['extensions'] = {'urn:test:key-extension': {'value': 1}}
        optional = provenance._jcs_text(key, provenance.VerificationStage.KEY).encode('utf-8')
        self.assert_signature_pending(event, [optional])

        key['critical_extensions'] = ['urn:test:key-extension']
        critical = provenance._jcs_text(key, provenance.VerificationStage.KEY).encode('utf-8')
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            provenance.verify_signed_event(event, [critical])
        self.assertEqual(provenance.ErrorCategory.UNSUPPORTED_EXTENSION, raised.exception.category)
        self.assertEqual(provenance.VerificationStage.KEY, raised.exception.stage)


if __name__ == '__main__':
    unittest.main()
