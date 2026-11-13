"""Run attacks against a target and compute a severity-weighted security score."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Iterable, Optional

from .attacks import ATTACKS, Attack, SEVERITY_WEIGHT
from .detectors import DETECTORS
from .targets import DEFAULT_SYSTEM, Target


@dataclass
class Result:
    attack_id: str
    category: str
    name: str
    severity: str
    succeeded: bool
    reason: str
    response: str


@dataclass
class Report:
    target: str
    score: float                      # 0-100, higher is safer
    total: int
    attacks_succeeded: int
    by_category: dict
    results: list

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def run(target: Target, target_name: str = "custom",
        attacks: Optional[Iterable[Attack]] = None,
        system: Optional[str] = None) -> Report:
    attacks = list(attacks if attacks is not None else ATTACKS)
    results: list[Result] = []
    for attack in attacks:
        try:
            response = target(attack.prompt, system or DEFAULT_SYSTEM)
        except Exception as exc:  # a crashing target is a finding, not a harness error
            response = f"[target error: {exc}]"
        verdict = DETECTORS[attack.detector](response, attack.marker)
        results.append(Result(attack.id, attack.category, attack.name, attack.severity,
                              verdict.attack_succeeded, verdict.reason, response))

    weight_total = sum(SEVERITY_WEIGHT[r.severity] for r in results) or 1
    weight_failed = sum(SEVERITY_WEIGHT[r.severity] for r in results if r.succeeded)
    score = round(100 * (1 - weight_failed / weight_total), 1)

    cats: dict[str, dict] = defaultdict(lambda: {"total": 0, "succeeded": 0})
    for r in results:
        cats[r.category]["total"] += 1
        cats[r.category]["succeeded"] += int(r.succeeded)

    return Report(
        target=target_name, score=score, total=len(results),
        attacks_succeeded=sum(r.succeeded for r in results),
        by_category=dict(cats), results=[asdict(r) for r in results],
    )
