from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
import re

COMMON = {"password", "123456", "qwerty", "letmein", "admin", "welcome"}

@dataclass(frozen=True)
class RuleResult:
    passed: bool
    message: str = ""

class PasswordRule(ABC):
    """Abstract base class for password rules."""
    @abstractmethod
    def check(self, pw: str) -> RuleResult:
        ...

@dataclass
class MinLengthRule(PasswordRule):
    min_length: int = 12
    def check(self, pw: str) -> RuleResult:
        ok = len(pw) >= self.min_length
        return RuleResult(ok, "" if ok else f"Use at least {self.min_length} characters.")

@dataclass
class ContainsLowerRule(PasswordRule):
    def check(self, pw: str) -> RuleResult:
        ok = bool(re.search(r"[a-z]", pw))
        return RuleResult(ok, "" if ok else "Add lowercase letters.")

@dataclass
class ContainsUpperRule(PasswordRule):
    def check(self, pw: str) -> RuleResult:
        ok = bool(re.search(r"[A-Z]", pw))
        return RuleResult(ok, "" if ok else "Add uppercase letters.")

@dataclass
class ContainsDigitRule(PasswordRule):
    def check(self, pw: str) -> RuleResult:
        ok = bool(re.search(r"\d", pw))
        return RuleResult(ok, "" if ok else "Add digits.")

@dataclass
class ContainsSymbolRule(PasswordRule):
    def check(self, pw: str) -> RuleResult:
        ok = bool(re.search(r"[^\w\s]", pw))
        return RuleResult(ok, "" if ok else "Add symbols (e.g., !@#$).")

@dataclass
class NotCommonRule(PasswordRule):
    def check(self, pw: str) -> RuleResult:
        ok = pw.lower() not in COMMON
        return RuleResult(ok, "" if ok else "Avoid common passwords.")

@dataclass
class NoTripleRepeatRule(PasswordRule):
    """Fail if any character repeats 3+ times in a row."""
    def check(self, pw: str) -> RuleResult:
        ok = not re.search(r"(.)\1\1", pw)
        return RuleResult(ok, "" if ok else "Avoid repeating a character 3+ times.")
