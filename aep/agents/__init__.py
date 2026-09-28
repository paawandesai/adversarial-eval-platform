"""Agent implementations for the adversarial-eval platform.

Each agent conforms to contracts/interfaces.py. The Red Team executes attacks
(writes AttackCase + AttackRun, never a verdict) and is the only agent here that
must NOT touch aep.target.audit — that grey-box reader is Judge-only.
"""
from aep.agents.mutations import TRANSFORMS, mutate
from aep.agents.red_team import (
    AttackGenerator,
    GenResult,
    RedTeam,
    RouterAttackGenerator,
    TemplateAttackGenerator,
)

__all__ = [
    "RedTeam",
    "AttackGenerator",
    "GenResult",
    "TemplateAttackGenerator",
    "RouterAttackGenerator",
    "mutate",
    "TRANSFORMS",
]
