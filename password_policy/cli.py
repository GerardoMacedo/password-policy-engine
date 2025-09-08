from __future__ import annotations
import argparse
import os
import getpass
import warnings

from .rules import (
    MinLengthRule, ContainsLowerRule, ContainsUpperRule,
    ContainsDigitRule, ContainsSymbolRule, NotCommonRule, NoTripleRepeatRule
)
from .policy import PasswordPolicy

def running_in_git_bash() -> bool:
    # Git Bash typically sets MSYSTEM and TERM like xterm
    return bool(os.environ.get("MSYSTEM")) and "xterm" in os.environ.get("TERM", "").lower()

def prompt_password(visible: bool) -> str:
    if visible or running_in_git_bash():
        return input("Enter password (visible): ")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        try:
            return getpass.getpass("Enter password (hidden): ")
        except Exception:
            return input("Enter password (visible): ")

def build_default_policy() -> PasswordPolicy:
    rules = [
        MinLengthRule(12),
        ContainsLowerRule(),
        ContainsUpperRule(),
        ContainsDigitRule(),
        ContainsSymbolRule(),
        NotCommonRule(),
        NoTripleRepeatRule(),
    ]
    # need 5 of 7 to “pass”
    return PasswordPolicy(rules=rules, required_score=5)

def main():
    parser = argparse.ArgumentParser(description="Password Policy Engine (OOP demo)")
    parser.add_argument("password", nargs="?", help="password to check; omit to be prompted")
    parser.add_argument("--visible", action="store_true", help="force visible prompt (useful on Git Bash)")
    args = parser.parse_args()

    pw = args.password if args.password is not None else prompt_password(visible=args.visible)

    policy = build_default_policy()
    report = policy.evaluate(pw)

    clamped = min(report.score, policy.required_score)
    verdicts = ["Very weak", "Weak", "OK", "Good", "Strong", "Very strong"]
    idx = max(0, min(len(verdicts) - 1, round((clamped / policy.required_score) * (len(verdicts) - 1))))
    verdict = verdicts[idx]

    print(f"Score: {clamped}/{policy.required_score} - {verdict}")
    if report.messages:
        print("Suggestions:")
        for m in report.messages:
            print(f"- {m}")

if __name__ == "__main__":
    main()
