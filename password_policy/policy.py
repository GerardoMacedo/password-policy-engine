from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
from .rules import PasswordRule, RuleResult

@dataclass
class PolicyReport:
    score: int
    max_score: int
    passed: bool
    messages: List[str]

@dataclass
class PasswordPolicy:
    rules: List[PasswordRule] = field(default_factory=list)
    required_score: int = 5  # how many rules must pass

    def evaluate(self, pw: str) -> PolicyReport:
        results: List[RuleResult] = [rule.check(pw) for rule in self.rules]
        score = sum(1 for r in results if r.passed)
        messages = [r.message for r in results if not r.passed and r.message]
        passed = score >= self.required_score
        return PolicyReport(score=score, max_score=len(self.rules), passed=passed, messages=messages)
