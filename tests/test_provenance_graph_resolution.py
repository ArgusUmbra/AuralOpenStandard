import copy
import json
from pathlib import Path
import random
import unittest

from aural import provenance


FIXTURES = Path(__file__).parent / 'fixtures' / 'provenance'


class _GraphBuilder:
    def __init__(self):
        self.template = json.loads(
            (FIXTURES / 'valid-original-acquired.json').read_bytes(),
        )
        self.records = {}

    @staticmethod
    def event_id(number):
        return f'urn:uuid:{number:08x}-2222-4333-8444-{number:012x}'

    def document(self, number, parents=()):
        document = copy.deepcopy(self.template)
        document['assertion']['event_id'] = self.event_id(number)
        document['assertion']['parents'] = sorted(
            ({
                'event_id': parent_id,
                'signed_event_digest': {
                    'algorithm': 'sha-256',
                    'value': digest,
                },
            } for parent_id, digest in parents),
            key=lambda reference: reference['event_id'],
        )
        return document

    @staticmethod
    def encode(document):
        return provenance._jcs_text(
            document, provenance.VerificationStage.RECORD,
        ).encode('utf-8')

    def add(self, number, parent_numbers=()):
        parents = [
            (self.event_id(parent_number), provenance._signed_event_sha256(
                self.records[parent_number],
            ))
            for parent_number in parent_numbers
        ]
        record = self.encode(self.document(number, parents))
        self.records[number] = record
        return record


class ProvenanceGraphResolutionTests(unittest.TestCase):
    def assert_error(self, category, operation, stage=provenance.VerificationStage.GRAPH):
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            operation()
        self.assertEqual(category, raised.exception.category)
        self.assertEqual(stage, raised.exception.stage)
        return raised.exception

    @staticmethod
    def resolve(records, limits=None):
        index = provenance._index_signed_event_records(records, limits)
        return index, provenance._resolve_signed_event_graph(index, limits)

    @staticmethod
    def ordered_ids(resolved):
        return tuple(
            record.validated.assertion['event_id'] for record in resolved.records
        )

    def synthetic_index(self, dependencies):
        """Make exact internal edges without requiring a SHA-256 fixed point."""
        builder = _GraphBuilder()
        digests = {number: f'{number:064x}' for number in dependencies}
        by_event_id = {}
        for number in sorted(dependencies):
            document = builder.document(number, [
                (builder.event_id(parent), digests[parent])
                for parent in dependencies[number]
            ])
            raw = builder.encode(document)
            validated = provenance._ValidatedRecord(
                document=document,
                assertion=document['assertion'],
            )
            by_event_id[builder.event_id(number)] = provenance._IndexedSignedRecord(
                record=raw,
                validated=validated,
                signed_event_sha256=digests[number],
            )
        return provenance._SignedEventIndex(by_event_id, 0)

    def test_single_root(self):
        builder = _GraphBuilder()
        root = builder.add(7)
        index, resolved = self.resolve([root])
        self.assertEqual(1, len(index.by_event_id))
        self.assertEqual((builder.event_id(7),), self.ordered_ids(resolved))
        self.assertEqual(1, resolved.maximum_depth)

    def test_linear_chain_is_parent_first(self):
        builder = _GraphBuilder()
        records = [builder.add(40)]
        records.append(builder.add(30, [40]))
        records.append(builder.add(20, [30]))
        records.append(builder.add(10, [20]))
        _, resolved = self.resolve(list(reversed(records)))
        self.assertEqual(
            tuple(builder.event_id(number) for number in (40, 30, 20, 10)),
            self.ordered_ids(resolved),
        )
        self.assertEqual(4, resolved.maximum_depth)

    def test_branching_graph_uses_event_id_ties(self):
        builder = _GraphBuilder()
        records = [builder.add(40)]
        records.append(builder.add(30, [40]))
        records.append(builder.add(20, [40]))
        _, resolved = self.resolve(records)
        self.assertEqual(
            tuple(builder.event_id(number) for number in (40, 20, 30)),
            self.ordered_ids(resolved),
        )
        self.assertEqual(2, resolved.maximum_depth)

    def test_diamond_and_shared_ancestor_are_not_a_cycle(self):
        builder = _GraphBuilder()
        records = [builder.add(40)]
        records.append(builder.add(30, [40]))
        records.append(builder.add(20, [40]))
        records.append(builder.add(10, [20, 30]))
        _, resolved = self.resolve(records)
        self.assertEqual(
            tuple(builder.event_id(number) for number in (40, 20, 30, 10)),
            self.ordered_ids(resolved),
        )
        self.assertEqual(3, resolved.maximum_depth)

    def test_multiple_independent_roots(self):
        builder = _GraphBuilder()
        records = [builder.add(number) for number in (30, 10, 20)]
        _, resolved = self.resolve(records)
        self.assertEqual(
            tuple(builder.event_id(number) for number in (10, 20, 30)),
            self.ordered_ids(resolved),
        )
        self.assertEqual(1, resolved.maximum_depth)

    def test_disconnected_valid_components(self):
        builder = _GraphBuilder()
        records = [builder.add(40), builder.add(20)]
        records.append(builder.add(30, [40]))
        records.append(builder.add(10, [20]))
        _, resolved = self.resolve(records)
        order = self.ordered_ids(resolved)
        self.assertLess(order.index(builder.event_id(40)), order.index(builder.event_id(30)))
        self.assertLess(order.index(builder.event_id(20)), order.index(builder.event_id(10)))
        self.assertEqual(2, resolved.maximum_depth)

    def test_identical_duplicates_do_not_add_nodes_or_depth(self):
        builder = _GraphBuilder()
        root = builder.add(20)
        child = builder.add(10, [20])
        index, resolved = self.resolve([child, root, child, root, root])
        self.assertEqual(2, len(index.by_event_id))
        self.assertEqual(3, index.duplicate_signed_records)
        self.assertEqual(2, len(resolved.records))
        self.assertEqual(2, resolved.maximum_depth)

    def test_reversed_and_randomized_input_order_are_identical(self):
        builder = _GraphBuilder()
        records = [builder.add(50), builder.add(40)]
        records.append(builder.add(30, [50]))
        records.append(builder.add(20, [40]))
        records.append(builder.add(10, [20, 30]))
        expected = self.ordered_ids(self.resolve(records)[1])
        self.assertEqual(expected, self.ordered_ids(self.resolve(list(reversed(records)))[1]))
        generator = random.Random(0xA007B2B)
        for _ in range(32):
            shuffled = list(records)
            generator.shuffle(shuffled)
            self.assertEqual(expected, self.ordered_ids(self.resolve(shuffled)[1]))

    def test_missing_parent_is_distinct_from_digest_mismatch(self):
        builder = _GraphBuilder()
        missing = builder.encode(builder.document(1, [
            (builder.event_id(2), '0' * 64),
        ]))
        index = provenance._index_signed_event_records([missing])
        self.assert_error(
            provenance.ErrorCategory.MISSING_PARENT,
            lambda: provenance._resolve_signed_event_graph(index),
        )
        self.assert_error(
            provenance.ErrorCategory.MISSING_PARENT,
            lambda: provenance.verify_signed_event_graph([missing], []),
        )

        root = builder.add(2)
        mismatch = builder.encode(builder.document(1, [
            (builder.event_id(2), '0' * 64),
        ]))
        index = provenance._index_signed_event_records([root, mismatch])
        self.assert_error(
            provenance.ErrorCategory.PARENT_DIGEST_MISMATCH,
            lambda: provenance._resolve_signed_event_graph(index),
        )
        self.assert_error(
            provenance.ErrorCategory.PARENT_DIGEST_MISMATCH,
            lambda: provenance.verify_signed_event_graph([root, mismatch], []),
        )

    def test_self_cycle_is_detected_defensively(self):
        index = self.synthetic_index({1: [1]})
        self.assert_error(
            provenance.ErrorCategory.CYCLE,
            lambda: provenance._resolve_signed_event_graph(index),
        )

    def test_two_event_cycle(self):
        index = self.synthetic_index({1: [2], 2: [1]})
        self.assert_error(
            provenance.ErrorCategory.CYCLE,
            lambda: provenance._resolve_signed_event_graph(index),
        )

    def test_longer_cycle(self):
        index = self.synthetic_index({1: [3], 2: [1], 3: [2]})
        self.assert_error(
            provenance.ErrorCategory.CYCLE,
            lambda: provenance._resolve_signed_event_graph(index),
        )

    def test_cycle_in_disconnected_component(self):
        index = self.synthetic_index({1: [], 2: [1], 3: [4], 4: [3]})
        self.assert_error(
            provenance.ErrorCategory.CYCLE,
            lambda: provenance._resolve_signed_event_graph(index),
        )

    def test_parent_fanout_boundary(self):
        builder = _GraphBuilder()
        roots = [builder.add(number) for number in range(1, 66)]
        at_limit = builder.add(100, range(1, 65))
        _, resolved = self.resolve(roots[:64] + [at_limit])
        self.assertEqual(65, len(resolved.records))
        self.assertEqual(2, resolved.maximum_depth)

        over_limit = builder.add(101, range(1, 66))
        index = provenance._index_signed_event_records(roots + [over_limit])
        self.assert_error(
            provenance.ErrorCategory.RESOURCE_LIMIT,
            lambda: provenance._resolve_signed_event_graph(index),
        )

    def test_graph_depth_boundary_counts_nodes(self):
        builder = _GraphBuilder()
        records = [builder.add(1)]
        for number in range(2, provenance.MAX_GRAPH_DEPTH + 2):
            records.append(builder.add(number, [number - 1]))

        at_limit = provenance._index_signed_event_records(
            records[:provenance.MAX_GRAPH_DEPTH],
        )
        resolved = provenance._resolve_signed_event_graph(at_limit)
        self.assertEqual(provenance.MAX_GRAPH_DEPTH, resolved.maximum_depth)

        over_limit = provenance._index_signed_event_records(records)
        self.assert_error(
            provenance.ErrorCategory.RESOURCE_LIMIT,
            lambda: provenance._resolve_signed_event_graph(over_limit),
        )

    def test_conflicting_duplicate_event_ids_fail_before_resolution(self):
        first = (FIXTURES / 'valid-original-acquired.json').read_bytes()
        second = (FIXTURES / 'invalid-signature.json').read_bytes()
        self.assert_error(
            provenance.ErrorCategory.EVENT_ID_COLLISION,
            lambda: provenance._index_signed_event_records([first, second]),
        )

    def test_malformed_parent_shape_is_rejected_upstream(self):
        builder = _GraphBuilder()
        document = builder.document(1)
        document['assertion']['parents'] = [{'event_id': builder.event_id(2)}]
        malformed = builder.encode(document)
        self.assert_error(
            provenance.ErrorCategory.SCHEMA,
            lambda: provenance._index_signed_event_records([malformed]),
            provenance.VerificationStage.RECORD,
        )

    def test_public_verifier_resolves_then_remains_fail_closed(self):
        root = (FIXTURES / 'valid-original-acquired.json').read_bytes()
        child = (FIXTURES / 'valid-received-with-parent.json').read_bytes()
        key = (FIXTURES / 'valid-key.json').read_bytes()
        self.assert_error(
            provenance.ErrorCategory.NOT_IMPLEMENTED,
            lambda: provenance.verify_signed_event_graph([child, root], [key]),
        )


if __name__ == '__main__':
    unittest.main()
