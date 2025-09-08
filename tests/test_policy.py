import unittest
from password_policy.policy import PasswordPolicy
from password_policy.rules import (
    MinLengthRule, ContainsLowerRule, ContainsUpperRule,
    ContainsDigitRule, ContainsSymbolRule, NotCommonRule, NoTripleRepeatRule
)

def default_policy():
    return PasswordPolicy(
        rules=[
            MinLengthRule(12),
            ContainsLowerRule(),
            ContainsUpperRule(),
            ContainsDigitRule(),
            ContainsSymbolRule(),
            NotCommonRule(),
            NoTripleRepeatRule(),
        ],
        required_score=5,
    )

def strict_policy():
    # require all 7 rules to pass
    return PasswordPolicy(
        rules=[
            MinLengthRule(12),
            ContainsLowerRule(),
            ContainsUpperRule(),
            ContainsDigitRule(),
            ContainsSymbolRule(),
            NotCommonRule(),
            NoTripleRepeatRule(),
        ],
        required_score=7,
    )

class TestPolicy(unittest.TestCase):
    def test_common_password_fails(self):
        r = default_policy().evaluate("password")
        self.assertFalse(r.passed)
        self.assertIn("Avoid common passwords.", r.messages)

    def test_strong_password_passes(self):
        r = default_policy().evaluate("Th3Good!Passw0rd")
        self.assertTrue(r.passed)
        self.assertGreaterEqual(r.score, 5)

    def test_triple_repeat_detected(self):
        r = strict_policy().evaluate("AAAbbb111!!!")
        self.assertFalse(r.passed)  # now fails because NoTripleRepeatRule fails
        # optional: also assert the message is present
        self.assertIn("Avoid repeating a character 3+ times.", r.messages)

if __name__ == "__main__":
    unittest.main()
