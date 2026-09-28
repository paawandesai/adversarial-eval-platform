"""
Target client for the Clinical Co-Pilot (contracts/target_api.md).

Import note: a top-level directory named `platform` cannot be imported as
`platform.target` — the stdlib `platform` module always wins, and adding a
`platform/__init__.py` would shadow the stdlib for the whole process. Until
the directory is renamed, put `<repo>/platform` on sys.path and import
`target.client` (tests/test_target_client.py, scripts/smoke_target.py).

`AuditReader` lives in `target.audit`, not here and not in `target.client`:
it is JUDGE-ONLY, and keeping it in its own module means "Red Team code
never imports target.audit" is a rule a grep or import-linter can enforce.
"""

from .client import (
    ROLES,
    TargetAuthError,
    TargetClient,
    TargetConfig,
    TargetTransportError,
    new_correlation_id,
)

__all__ = [
    "ROLES",
    "TargetAuthError",
    "TargetClient",
    "TargetConfig",
    "TargetTransportError",
    "new_correlation_id",
]
