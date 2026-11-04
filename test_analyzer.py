import unittest

from password_analyzer import analyze_password, generate_password


class TestPasswordAnalyzer(unittest.TestCase):
    def test_empty_password_is_not_rated(self):
        self.assertEqual(analyze_password("")["strength"], "Not rated")

    def test_common_password_is_weak(self):
        self.assertEqual(analyze_password("password123")["strength"], "Weak")

    def test_short_password_is_weak(self):
        self.assertEqual(analyze_password("Ab1!")["strength"], "Weak")

    def test_predictable_sequence_is_weak(self):
        self.assertEqual(analyze_password("Abc1234!xyz")["strength"], "Weak")

    def test_long_varied_password_can_be_strong(self):
        self.assertEqual(analyze_password("River!Cloud8#Garden")["strength"], "Strong")

    def test_analysis_contains_checks_and_advice(self):
        result = analyze_password("example")
        self.assertIn("checks", result)
        self.assertTrue(result["advice"])

    def test_generator_has_minimum_length_and_character_classes(self):
        password = generate_password(16)
        self.assertEqual(len(password), 16)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(c in "!@#$%^&*()-_=+?" for c in password))

    def test_generator_rejects_short_length(self):
        with self.assertRaises(ValueError):
            generate_password(8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
