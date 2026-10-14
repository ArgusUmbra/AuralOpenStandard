import base64
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

try:
    import cryptography
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    cryptography = None
    InvalidSignature = None
    Ed25519PublicKey = None


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'fixtures' / 'provenance'
ED25519_P = (1 << 255) - 19
ED25519_L = (1 << 252) + 27742317777372353535851937790883648493
SMALL_ORDER_Y = {
    0,
    1,
    ED25519_P - 1,
    int('7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7', 16),
    int('05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826', 16),
}


def independent_jcs(value, containing_depth=0):
    if value is None or isinstance(value, bool):
        return json.dumps(value, separators=(',', ':'))
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9007199254740991:
            raise ValueError('unsafe integer')
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value) or value == 0 and math.copysign(1, value) < 0:
            raise ValueError('unsupported number')
        raise ValueError('floating-point values are outside the AURAL profile')
    depth = containing_depth + 1
    if depth > 32:
        raise ValueError('excessive depth')
    if isinstance(value, list):
        return '[' + ','.join(independent_jcs(item, depth) for item in value) + ']'
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode('utf-16-be', errors='surrogatepass'))
        return '{' + ','.join(
            json.dumps(key, ensure_ascii=False, separators=(',', ':')) + ':'
            + independent_jcs(value[key], depth)
            for key in keys
        ) + '}'
    raise ValueError('unsupported JSON type')


def strict_base64url(value, expected_length):
    if not isinstance(value, str) or '=' in value:
        raise ValueError('noncanonical base64url')
    decoded = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    if len(decoded) != expected_length:
        raise ValueError('wrong decoded length')
    if base64.urlsafe_b64encode(decoded).rstrip(b'=').decode('ascii') != value:
        raise ValueError('noncanonical base64url')
    return decoded


def independent_point_profile(encoded):
    if len(encoded) != 32:
        return False
    sign = encoded[31] >> 7
    y = int.from_bytes(encoded, 'little') & ((1 << 255) - 1)
    if y >= ED25519_P or sign and y in {1, ED25519_P - 1}:
        return False
    return y not in SMALL_ORDER_Y


def independent_ed25519_profile(public_key, message, signature):
    if (len(signature) != 64 or not independent_point_profile(public_key)
            or not independent_point_profile(signature[:32])
            or int.from_bytes(signature[32:], 'little') >= ED25519_L):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


class ProvenanceSignatureTests(unittest.TestCase):
    def setUp(self):
        self.expected = json.loads((CORPUS / 'expected.json').read_text(encoding='utf-8'))

    def test_fixture_hashes_key_id_and_record_digest(self):
        actual_files = {path.name for path in CORPUS.iterdir()
                        if path.is_file() and path.name != 'expected.json'}
        self.assertEqual(set(self.expected['files_sha256']), actual_files)
        for name, digest in self.expected['files_sha256'].items():
            with self.subTest(file=name):
                self.assertEqual(digest, hashlib.sha256((CORPUS / name).read_bytes()).hexdigest())

        for name, case in self.expected['cases'].items():
            with self.subTest(case=name):
                payload = (CORPUS / case['event']).read_bytes()
                self.assertEqual(case['event_sha256'], hashlib.sha256(payload).hexdigest())

        key = json.loads((CORPUS / 'valid-key.json').read_bytes())
        public_key = base64.urlsafe_b64decode(key['public_key'] + '=')
        self.assertEqual(32, len(public_key))
        material = b'AURAL-KEY-ID-V1\x00Ed25519\x00' + public_key
        computed = 'urn:aural:key:ed25519:' + hashlib.sha256(material).hexdigest()
        self.assertEqual(key['key_id'], computed)
        self.assertEqual(self.expected['public_key']['key_id'], computed)

        record = (CORPUS / 'valid-original-acquired.json').read_bytes()
        digest = hashlib.sha256(b'AURAL-SIGNED-EVENT-V1\x00' + record).hexdigest()
        self.assertEqual(self.expected['golden_vector']['signed_event_digest'], digest)
        self.assertEqual(self.expected['golden_vector']['record_length'], len(record))
        child = json.loads((CORPUS / 'valid-received-with-parent.json').read_bytes())
        self.assertEqual(
            self.expected['golden_vector']['signed_event_digest'],
            child['assertion']['parents'][0]['signed_event_digest']['value'],
        )
        self.assertEqual(
            json.loads(record)['assertion']['event_id'],
            child['assertion']['parents'][0]['event_id'],
        )

    def test_golden_signature_input_is_exact_domain_plus_assertion(self):
        assertion = (CORPUS / 'valid-original-acquired.assertion.json').read_bytes()
        signature_input = (CORPUS / 'valid-original-acquired.signature-input.bin').read_bytes()
        self.assertEqual(b'AURAL-PROVENANCE-EVENT-V1\x00' + assertion, signature_input)
        golden = self.expected['golden_vector']
        self.assertEqual(golden['assertion_length'], len(assertion))
        self.assertEqual(golden['assertion_sha256'], hashlib.sha256(assertion).hexdigest())
        self.assertEqual(golden['signature_input_length'], len(signature_input))
        self.assertEqual(golden['signature_input_sha256'], hashlib.sha256(signature_input).hexdigest())

    @unittest.skipUnless(
        Ed25519PublicKey is not None,
        'independent Ed25519 coverage missing: install Python cryptography explicitly',
    )
    def test_python_cryptography_independently_verifies_positive_vectors(self):
        key = json.loads((CORPUS / 'valid-key.json').read_text(encoding='utf-8'))
        public_key = strict_base64url(key['public_key'], 32)
        material = b'AURAL-KEY-ID-V1\x00Ed25519\x00' + public_key
        self.assertEqual(
            key['key_id'], 'urn:aural:key:ed25519:' + hashlib.sha256(material).hexdigest(),
        )
        positive = [case for case in self.expected['cases'].values() if case['outcome'] == 'accept']
        self.assertEqual(3, len(positive))
        for case in positive:
            with self.subTest(event=case['event'], cryptography=cryptography.__version__):
                raw = (CORPUS / case['event']).read_bytes()
                record = json.loads(raw.decode('utf-8'))
                self.assertEqual(
                    raw, independent_jcs(record).encode('utf-8'), 'independent JCS record mismatch',
                )
                assertion_bytes = independent_jcs(record['assertion']).encode('utf-8')
                signature_input = b'AURAL-PROVENANCE-EVENT-V1\x00' + assertion_bytes
                signature = strict_base64url(record['signature'], 64)
                Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signature_input)
                signed_digest = hashlib.sha256(
                    b'AURAL-SIGNED-EVENT-V1\x00' + raw,
                ).hexdigest()
                self.assertEqual(case['signed_event_digest'], signed_digest)

        golden = self.expected['golden_vector']
        golden_raw = (CORPUS / 'valid-original-acquired.json').read_bytes()
        golden_record = json.loads(golden_raw)
        golden_assertion = independent_jcs(golden_record['assertion']).encode('utf-8')
        self.assertEqual(golden['assertion_sha256'], hashlib.sha256(golden_assertion).hexdigest())
        self.assertEqual(
            golden['signature_input_sha256'],
            hashlib.sha256(b'AURAL-PROVENANCE-EVENT-V1\x00' + golden_assertion).hexdigest(),
        )
        self.assertEqual(
            golden['signed_event_digest'],
            hashlib.sha256(b'AURAL-SIGNED-EVENT-V1\x00' + golden_raw).hexdigest(),
        )

    @unittest.skipUnless(
        Ed25519PublicKey is not None,
        'negative acceptance-set coverage missing: install Python cryptography explicitly',
    )
    def test_python_cryptography_matches_adversarial_acceptance_policy(self):
        vectors = json.loads((CORPUS / 'ed25519-adversarial.json').read_text(encoding='utf-8'))
        for vector in vectors['vectors']:
            with self.subTest(vector=vector['name'], cryptography=cryptography.__version__):
                actual = independent_ed25519_profile(
                    bytes.fromhex(vector['public_key']),
                    bytes.fromhex(vector['message']),
                    bytes.fromhex(vector['signature']),
                )
                self.assertEqual(vector['expected'], actual)

    @unittest.skipUnless(shutil.which('java'), 'independent Java Ed25519 provider is not installed')
    def test_java_provider_independently_matches_vectors(self):
        vectors = json.loads((CORPUS / 'ed25519-adversarial.json').read_text(encoding='utf-8'))
        inputs = []
        expected = []
        for vector in vectors['vectors']:
            inputs.append(' '.join((vector['public_key'], vector['message'], vector['signature'])))
            expected.append(vector['expected'])

        key = json.loads((CORPUS / 'valid-key.json').read_text(encoding='utf-8'))
        public_key = strict_base64url(key['public_key'], 32).hex()
        for case in self.expected['cases'].values():
            if case['outcome'] != 'accept':
                continue
            record = json.loads((CORPUS / case['event']).read_text(encoding='utf-8'))
            message = (b'AURAL-PROVENANCE-EVENT-V1\x00'
                       + independent_jcs(record['assertion']).encode('utf-8'))
            signature = strict_base64url(record['signature'], 64)
            inputs.append(' '.join((public_key, message.hex(), signature.hex())))
            expected.append(True)

        completed = subprocess.run(
            ['java', str(ROOT / 'tests' / 'Ed25519CrossCheck.java')],
            input='\n'.join(inputs) + '\n', capture_output=True, text=True,
            check=False, timeout=30,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        lines = completed.stdout.splitlines()
        self.assertTrue(lines[0].startswith('PROVIDER:'), completed.stdout)
        self.assertEqual(expected, [line == '1' for line in lines[1:]])

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_independent_node_validator_agrees_with_corpus(self):
        validator_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        for name, case in self.expected['cases'].items():
            event = str(CORPUS / case['event'])
            keys = [str(CORPUS / value) for value in case['keys']]
            package = str(CORPUS / case['package'])
            script = (
                f"import {{ verifySignedEventFiles }} from {json.dumps(validator_uri)};"
                "try {"
                f" const result = await verifySignedEventFiles({json.dumps(event)},"
                f" {json.dumps(keys)}, {json.dumps(package)});"
                " console.log(JSON.stringify(result));"
                "} catch (error) {"
                " console.error(`CATEGORY:${error.category ?? 'internal'} ${error.message}`);"
                " process.exitCode = 1;"
                "}"
            )
            with self.subTest(case=name):
                completed = subprocess.run(
                    ['node', '--input-type=module', '--eval', script],
                    capture_output=True, text=True, check=False, timeout=15,
                )
                accepted = case['outcome'] == 'accept'
                self.assertEqual(accepted, completed.returncode == 0, completed.stderr)
                if accepted:
                    result = json.loads(completed.stdout)
                    self.assertEqual('signature_valid', result['status'])
                    self.assertEqual('verified', result['asset_integrity'])
                    self.assertEqual('not_established', result['investigator_identity'])
                    self.assertEqual('not_evaluated', result['key_trust'])
                    self.assertEqual('claimed_only', result['time_assurance'])
                    self.assertEqual('not_established', result['history_completeness'])
                else:
                    self.assertIn(f"CATEGORY:{case['error_category']}", completed.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_record_size_is_bounded_before_json_processing(self):
        validator_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        script = (
            f"import {{ verifySignedEvent }} from {json.dumps(validator_uri)};"
            "try { verifySignedEvent(Buffer.alloc(257, 0x7b), [], {maxRecord: 256}); }"
            "catch (error) { console.error(`CATEGORY:${error.category}`); process.exitCode = 1; }"
        )
        completed = subprocess.run(
            ['node', '--input-type=module', '--eval', script],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(1, completed.returncode)
        self.assertIn('CATEGORY:resource_limit', completed.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_node_matches_adversarial_acceptance_policy(self):
        validator_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        vector_path = str(CORPUS / 'ed25519-adversarial.json')
        script = (
            "import {readFile} from 'node:fs/promises';"
            f"import {{verifyEd25519Profile}} from {json.dumps(validator_uri)};"
            f"const fixture=JSON.parse(await readFile({json.dumps(vector_path)},'utf8'));"
            "const results=fixture.vectors.map(v=>verifyEd25519Profile("
            "Buffer.from(v.public_key,'hex'),Buffer.from(v.message,'hex'),"
            "Buffer.from(v.signature,'hex')));console.log(JSON.stringify(results));"
        )
        completed = subprocess.run(
            ['node', '--input-type=module', '--eval', script],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        expected = [item['expected'] for item in json.loads(
            (CORPUS / 'ed25519-adversarial.json').read_text(encoding='utf-8')
        )['vectors']]
        self.assertEqual(expected, json.loads(completed.stdout))

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_file_wrapper_enforces_limits_before_bulk_reads(self):
        validator_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oversized_event = root / 'oversized-event.json'
            with oversized_event.open('wb') as output:
                output.truncate(1024 * 1024 + 1)
            oversized_key = root / 'oversized-key.json'
            with oversized_key.open('wb') as output:
                output.truncate(16 * 1024 + 1)
            valid_event = str(CORPUS / 'valid-original-acquired.json')
            valid_key = str(CORPUS / 'valid-key.json')
            checks = [
                (str(oversized_event), [valid_key], {}, 'event physical size'),
                (valid_event, [str(oversized_key)], {}, 'key physical size'),
                (valid_event, [valid_key, valid_key], {'maxKeyRecords': 1}, 'key count'),
                (valid_event, [valid_key, valid_key], {'maxKeyData': 300}, 'aggregate key data'),
            ]
            for event, keys, options, label in checks:
                script = (
                    f"import {{verifySignedEventFiles}} from {json.dumps(validator_uri)};"
                    "try { await verifySignedEventFiles("
                    f"{json.dumps(event)},{json.dumps(keys)},undefined,{json.dumps(options)}); }}"
                    "catch(error){console.error(`CATEGORY:${error.category}`);process.exitCode=1;}"
                )
                with self.subTest(limit=label):
                    completed = subprocess.run(
                        ['node', '--input-type=module', '--eval', script],
                        capture_output=True, text=True, check=False, timeout=10,
                    )
                    self.assertEqual(1, completed.returncode, completed.stderr)
                    self.assertIn('CATEGORY:resource_limit', completed.stderr)

    def test_file_wrapper_uses_stable_bounded_positional_io(self):
        source = (ROOT / 'interop' / 'validate_provenance.mjs').read_text(encoding='utf-8')
        self.assertNotIn('readFile(', source)
        self.assertNotIn('Promise.all(', source)
        self.assertIn('handle = await open(filePath, safeOpenFlags(label))', source)
        self.assertIn('pathBefore = await lstat(filePath, { bigint: true })', source)
        self.assertIn("const before = await handle.stat({ bigint: true })", source)
        self.assertIn('await handle.read(raw, offset, raw.length - offset, offset)', source)
        self.assertIn('!sameSnapshot(before, after)', source)
        self.assertIn('await handle.close()', source)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_node_readers_reject_directories(self):
        provenance_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        aural_uri = (ROOT / 'interop' / 'validate_aural.mjs').as_uri()
        event = CORPUS / 'valid-original-acquired.json'
        key = CORPUS / 'valid-key.json'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = [
                ('event-directory', 'provenance', root, []),
                ('key-directory', 'provenance', event, [root]),
                ('package-directory', 'package', root, []),
                ('bound-package-directory', 'bound', event, [key]),
            ]
            encoded = [
                [name, kind, str(path), [str(item) for item in keys]]
                for name, kind, path, keys in cases
            ]
            script = (
                f"import {{verifySignedEventFiles}} from {json.dumps(provenance_uri)};"
                f"import {{verify}} from {json.dumps(aural_uri)};"
                f"const cases={json.dumps(encoded)};const results=[];"
                "for(const [name,kind,path,keys] of cases){try{"
                f"if(kind==='package')await verify(path);"
                f"else if(kind==='bound')await verifySignedEventFiles(path,keys,{json.dumps(str(root))});"
                "else await verifySignedEventFiles(path,keys);"
                "results.push([name,'accepted']);}catch(error){results.push([name,"
                "error.category??null,error.auralValidationFailure===true]);}}"
                "console.log(JSON.stringify(results));"
            )
            completed = subprocess.run(
                ['node', '--input-type=module', '--eval', script],
                capture_output=True, text=True, check=False, timeout=10,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        results = {item[0]: item[1:] for item in json.loads(completed.stdout)}
        self.assertEqual(['resource_limit', False], results['event-directory'])
        self.assertEqual(['resource_limit', False], results['key-directory'])
        self.assertEqual([None, True], results['package-directory'])
        self.assertEqual(['package_integrity', False], results['bound-package-directory'])

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_node_readers_reject_symlinks_where_supported(self):
        provenance_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        aural_uri = (ROOT / 'interop' / 'validate_aural.mjs').as_uri()
        event = CORPUS / 'valid-original-acquired.json'
        key = CORPUS / 'valid-key.json'
        package = ROOT / 'tests' / 'fixtures' / 'conformance' / 'valid-minimal.aural'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_link = root / 'event-link.json'
            key_link = root / 'key-link.json'
            package_link = root / 'package-link.aural'
            try:
                event_link.symlink_to(event)
                key_link.symlink_to(key)
                package_link.symlink_to(package)
            except OSError as exc:
                self.skipTest(f'symbolic-link creation is unavailable: {exc}')
            script = (
                f"import {{verifySignedEventFiles}} from {json.dumps(provenance_uri)};"
                f"import {{verify}} from {json.dumps(aural_uri)};const results=[];"
                f"try{{await verifySignedEventFiles({json.dumps(str(event_link))},[]);}}"
                "catch(error){results.push(error.category);};"
                f"try{{await verifySignedEventFiles({json.dumps(str(event))},"
                f"[{json.dumps(str(key_link))}]);}}catch(error){{results.push(error.category);}};"
                f"try{{await verify({json.dumps(str(package_link))});}}"
                "catch(error){results.push(error.auralValidationFailure===true);};"
                "console.log(JSON.stringify(results));"
            )
            completed = subprocess.run(
                ['node', '--input-type=module', '--eval', script],
                capture_output=True, text=True, check=False, timeout=10,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(
            ['resource_limit', 'resource_limit', True], json.loads(completed.stdout),
        )

    @unittest.skipUnless(
        os.name == 'posix' and hasattr(os, 'mkfifo') and shutil.which('node'),
        'actual Node FIFO check requires POSIX and Node.js',
    )
    def test_node_readers_reject_fifo_without_blocking(self):
        provenance_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        aural_uri = (ROOT / 'interop' / 'validate_aural.mjs').as_uri()
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / 'input.fifo'
            os.mkfifo(fifo)
            script = (
                f"import {{verifySignedEventFiles}} from {json.dumps(provenance_uri)};"
                f"import {{verify}} from {json.dumps(aural_uri)};"
                "const results=[];"
                f"try{{await verifySignedEventFiles({json.dumps(str(fifo))},[]);}}"
                "catch(error){results.push(error.category);};"
                f"try{{await verify({json.dumps(str(fifo))});}}"
                "catch(error){results.push(error.auralValidationFailure===true);};"
                "console.log(JSON.stringify(results));"
            )
            completed = subprocess.run(
                ['node', '--input-type=module', '--eval', script],
                capture_output=True, text=True, check=False, timeout=5,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(['resource_limit', True], json.loads(completed.stdout))

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_generator_is_deterministic_and_emits_no_private_seed(self):
        before = {path.name: path.read_bytes() for path in CORPUS.iterdir() if path.is_file()}
        subprocess.run(
            ['node', str(ROOT / 'tools' / 'generate_provenance_fixtures.mjs')],
            cwd=ROOT, check=True, capture_output=True, timeout=15,
        )
        after = {path.name: path.read_bytes() for path in CORPUS.iterdir() if path.is_file()}
        self.assertEqual(before, after)
        test_seed_hex = b'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
        test_seed_raw = bytes.fromhex(test_seed_hex.decode('ascii'))
        for name, payload in after.items():
            with self.subTest(file=name):
                self.assertNotIn(test_seed_hex, payload)
                self.assertNotIn(test_seed_raw, payload)
        self.assertFalse(self.expected['private_key_material_included'])


if __name__ == '__main__':
    unittest.main()
