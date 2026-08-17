import unittest
from password_analyzer import analyze_password, calculate_entropy, check_nist_compliance, normalize_leetspeak

class TestPasswordAnalyzer(unittest.TestCase):

    def test_leetspeak_normalization(self):
        self.assertEqual(normalize_leetspeak("P@ssw0rd3"), "passwords")
        self.assertEqual(normalize_leetspeak("Adm!n123"), "admin123")

    def test_entropy_calculation(self):
        entropy_weak, _, _ = calculate_entropy("123456")
        entropy_strong, _, _ = calculate_entropy("C0mpl3x#P@ssw0rd!2026")
        self.assertGreater(entropy_strong, entropy_weak)
        self.assertGreater(entropy_strong, 60.0)

    def test_nist_compliance_weak(self):
        res = check_nist_compliance("123456")
        self.assertFalse(res["is_compliant"])
        self.assertTrue(any("minimum length" in issue.lower() for issue in res["issues"]))

    def test_nist_compliance_strong(self):
        res = check_nist_compliance("correct-horse-battery-staple")
        self.assertTrue(res["is_compliant"])
        self.assertEqual(len(res["issues"]), 0)

    def test_analyze_password(self):
        analysis = analyze_password("SuperSecure#Passphrase2026")
        self.assertIn("entropy", analysis)
        self.assertIn("score", analysis)
        self.assertGreaterEqual(analysis["score"], 80)
        self.assertEqual(analysis["badge_color"], "emerald")

    def test_hash_format_identification(self):
        from password_analyzer import identify_hash_format
        shadow_hash = identify_hash_format("$6$saltsalt$hashstring")
        self.assertIn("SHA-512", shadow_hash["algorithm"])
        ntlm_hash = identify_hash_format("31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertIn("NTLM", ntlm_hash["algorithm"])

if __name__ == "__main__":
    unittest.main()
