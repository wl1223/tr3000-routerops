from pathlib import Path

import pytest

from routerops.evidence import EvidenceStore
from routerops.models import RunMode
from routerops.safety import SafetyPolicy
from routerops.tools import ToolFacade, build_registry
from routerops.tools.backends import MockRouterBackend


@pytest.fixture
def make_facade(tmp_path: Path):
    def factory(scenario: str = "healthy", mode: RunMode = RunMode.DIAGNOSE):
        backend = MockRouterBackend(scenario)
        facade = ToolFacade(
            backend,
            build_registry(),
            SafetyPolicy(),
            EvidenceStore(tmp_path / "evidence"),
            mode,
        )
        return backend, facade

    return factory

