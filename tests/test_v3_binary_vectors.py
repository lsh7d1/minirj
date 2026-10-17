import unittest

import local_data
from minirj.crypto.v3 import V3Generator, select_mode


class TestV3BinaryVectors(unittest.TestCase):
    def test_legacy_prepare_data_modes_match_target_elf(self):
        document = local_data.load("f2.json")
        self.assertIn("0x0056ffa0", document["function"])
        vectors = document["vectors"]
        self.assertEqual([item["mode"] for item in vectors], list(range(5)))

        generator = V3Generator()
        for item in vectors:
            challenge = bytes.fromhex(item["challenge"])
            with self.subTest(mode=item["mode"]):
                self.assertEqual(
                    generator.generate_payload(challenge).decode("ascii"),
                    item["payload"],
                )

    def test_expanded_explicit_modes_match_observed_target(self):
        document = local_data.load("f1.json")
        self.assertEqual(document['status'], 'target_observed')
        self.assertEqual(len(document['vectors']), 110)
        generator = V3Generator()
        mismatched_selectors = 0
        for item in document['vectors']:
            challenge = bytes.fromhex(item['challenge'])
            mismatched_selectors += select_mode(challenge) != item['mode']
            with self.subTest(case=item['case']):
                self.assertEqual(generator.generate_payload(challenge, mode=item['mode']).decode(),
                                 item['payload'])
                if select_mode(challenge) == item['mode']:
                    self.assertEqual(generator.generate_payload(challenge).decode(), item['payload'])
        self.assertGreater(mismatched_selectors, 0)

    def test_real_selector_instruction_slice_matches_target(self):
        document = local_data.load("f1.json")
        self.assertEqual(len(document['selector_vectors']), 12)
        old_formula_disagreements = 0
        for item in document['selector_vectors']:
            challenge = bytes.fromhex(item['challenge'])
            with self.subTest(case=item['case']):
                self.assertEqual(select_mode(challenge), item['mode'])
                old_formula_disagreements += (challenge[0] + challenge[3]) % 5 != item['mode']
        self.assertGreater(old_formula_disagreements, 0)

    def test_explicit_mode_validation(self):
        generator = V3Generator()
        for mode in (-1, 5, True, 1.0, '1'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                generator.generate_payload(bytes(16), mode=mode)
        with self.assertRaises(ValueError):
            generator.generate_payload(bytes(15), mode=0)


if __name__ == "__main__":
    unittest.main()
