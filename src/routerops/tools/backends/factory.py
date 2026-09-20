from routerops.config import Settings
from routerops.fixtures import ReplayRouterAdapter
from routerops.tools.backends.base import RouterBackend
from routerops.tools.backends.mock import MockRouterBackend
from routerops.tools.backends.ssh import ParamikoSSHAdapter


def build_backend(settings: Settings) -> RouterBackend:
    if settings.backend == "mock":
        return MockRouterBackend(settings.scenario)
    if settings.backend == "replay":
        assert settings.fixture_replay_dir is not None
        return ReplayRouterAdapter(settings.fixture_replay_dir)
    return ParamikoSSHAdapter(settings.device_profile())

