import json

import pytest

from redteam.attacks import ATTACKS, categories
from redteam.cli import main
from redteam.detectors import canary_leak, marker_echo, pii_leak
from redteam.report import grade, to_json, to_markdown
from redteam.runner import run
from redteam.targets import CANARY, build_target, guarded_target, vulnerable_target


def test_attack_ids_unique_and_valid():
    ids = [a.id for a in ATTACKS]
    assert len(ids) == len(set(ids))
    assert {"prompt_injection", "indirect_injection", "system_prompt_leak",
            "pii_exfiltration", "jailbreak", "obfuscation"} <= set(categories())


def test_detectors():
    assert canary_leak(f"x {CANARY} y", "").attack_succeeded
    assert not canary_leak("nothing", "").attack_succeeded
    assert marker_echo("PWNED-1", "PWNED-1").attack_succeeded
    assert not marker_echo("I can't say PWNED-1", "PWNED-1").attack_succeeded
    assert pii_leak("mail me at a@b.com", "").attack_succeeded
    assert not pii_leak("hello", "").attack_succeeded


def test_vulnerable_target_scores_low():
    report = run(vulnerable_target, "mock-vulnerable")
    assert report.score < 20
    assert report.attacks_succeeded == report.total


def test_guarded_target_better_but_not_perfect():
    vuln = run(vulnerable_target).score
    guarded = run(guarded_target, "mock-guarded")
    assert guarded.score > vuln
    assert guarded.score < 100  # obfuscation and indirect injection still get through
    cats = guarded.by_category
    assert cats["obfuscation"]["succeeded"] > 0
    assert cats["indirect_injection"]["succeeded"] > 0
    assert cats["system_prompt_leak"]["succeeded"] == 0 or cats["system_prompt_leak"]["succeeded"] < cats["system_prompt_leak"]["total"]


def test_safe_target_scores_100():
    report = run(lambda prompt, system=None: "I can't help with that.")
    assert report.score == 100.0 and report.attacks_succeeded == 0


def test_crashing_target_does_not_crash_harness():
    def boom(prompt, system=None):
        raise RuntimeError("down")
    report = run(boom)
    assert report.total == len(ATTACKS)


def test_report_renderers():
    report = run(guarded_target, "mock-guarded")
    assert "Security score" in to_markdown(report)
    assert json.loads(to_json(report))["target"] == "mock-guarded"
    assert grade(95) == "A" and grade(10) == "F"


def test_build_target_unknown():
    with pytest.raises(ValueError):
        build_target("nope")


def test_cli_fail_under(tmp_path, capsys):
    out = tmp_path / "report"
    assert main(["--target", "mock-vulnerable", "--out", str(out), "--fail-under", "50"]) == 1
    assert (tmp_path / "report.md").exists() and (tmp_path / "report.json").exists()
    assert main(["--target", "mock-guarded", "--fail-under", "10"]) == 0
